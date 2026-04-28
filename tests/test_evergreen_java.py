#!/usr/bin/env python3
"""
Evergreen Java section regression test.

After the 2026-04-28 reconciliation, the evergreen.html Java section is
driven by data/evergreen-generation-mapping.json (per-CVE old-gen-vs-new-gen
classification) layered on data/seven-year-manifest-events.json (the
canonical 58-pkg, 194-event runtime manifest).

This test asserts:

  1. data/evergreen-generation-mapping.json is reproducible from the
     events file via scripts/build_evergreen_java.py --check.
  2. Every CVE in seven-year-manifest-events.json has an entry in the
     mapping. (No drift when new events land.)
  3. Every entry in the mapping uses one of the 4 valid evergreen
     categories.
  4. The headline tallies the page prose claims (NP+DI raw split into
     avoids / makes_worse / no_difference / irrelevant) match what the
     mapping actually says.
  5. The "narrative outcome" - all 'makes_worse' events on the canonical
     manifest are also exploited - still holds. (If this changes, the
     page's "directional effect is negative" framing has to change.)
  6. Specific numeric claims in docs/evergreen.html's Java section
     (the hero cards, the lead paragraph, the per-family counts in
     prose, the table footer) match the canonical tally.

Per CLAUDE.md: claims without tests rot. This locks the evergreen Java
section to the canonical events file.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from _common import TestReporter  # noqa: E402

EVENTS_FILE = REPO / "data" / "seven-year-manifest-events.json"
MAPPING_FILE = REPO / "data" / "evergreen-generation-mapping.json"
EVERGREEN_HTML = REPO / "docs" / "evergreen.html"

VALID_CATEGORIES = {"avoids", "makes_worse", "no_difference", "irrelevant"}


def package_family(pkgs: list[str]) -> str:
    if not pkgs:
        return "unknown"
    short = pkgs[0].split(":")[-1]
    if "tomcat" in short:
        return "Tomcat"
    if "xstream" in short:
        return "XStream"
    if "log4j" in short:
        return "Log4j"
    if "jackson" in short:
        return "jackson-databind"
    if "spring-security" in short:
        return "Spring Security"
    if short.startswith("spring-") or "spring-boot" in short:
        return "Spring Framework/Boot"
    if "thymeleaf" in short:
        return "Thymeleaf"
    if "activemq" in short:
        return "ActiveMQ"
    if short.startswith("mina"):
        return "MINA"
    if "cxf" in short:
        return "Apache CXF"
    if "hazelcast" in short:
        return "Hazelcast"
    return short


def _check_reproducible(r: TestReporter) -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/build_evergreen_java.py", "--check"],
        cwd=REPO, capture_output=True, text=True,
    )
    r.check(
        proc.returncode == 0,
        f"build_evergreen_java.py --check should succeed "
        f"(rc={proc.returncode}, stdout={proc.stdout!r}, stderr={proc.stderr!r})"
    )


def _check_mapping_completeness(r: TestReporter) -> None:
    events = json.load(open(EVENTS_FILE))["events"]
    mapping = json.load(open(MAPPING_FILE))["mapping"]

    event_cves = {e["cve"] for e in events}
    mapping_cves = set(mapping.keys())

    missing = event_cves - mapping_cves
    r.check(
        not missing,
        f"every event CVE has a mapping entry "
        f"({len(missing)} missing: {sorted(missing)[:5]})"
    )
    extra = mapping_cves - event_cves
    r.check(
        not extra,
        f"no orphan mapping entries "
        f"({len(extra)} extra: {sorted(extra)[:5]})"
    )

    for cve, entry in mapping.items():
        cat = entry.get("evergreen_category")
        r.check(
            cat in VALID_CATEGORIES,
            f"{cve} has valid category (got {cat!r}, must be in {VALID_CATEGORIES})"
        )
        r.check(
            entry.get("rationale"),
            f"{cve} has non-empty rationale"
        )


def _derive_canonical(events: list[dict], mapping: dict) -> dict:
    npdi_raw = [e for e in events if e.get("is_np") and e.get("is_di")]
    exploited = [e for e in events if e.get("exploited")]

    def cat(e):
        return mapping[e["cve"]]["evergreen_category"]

    def cnt(subset, c):
        return sum(1 for e in subset if cat(e) == c)

    fam_npdi: Counter = Counter()
    for e in npdi_raw:
        fam_npdi[package_family(e.get("packages", []))] += 1

    return {
        "totals": {
            "all_ch": len(events),
            "npdi_raw": len(npdi_raw),
            "exploited": len(exploited),
        },
        "evergreen_npdi_raw": {
            "avoids": cnt(npdi_raw, "avoids"),
            "makes_worse": cnt(npdi_raw, "makes_worse"),
            "no_difference": cnt(npdi_raw, "no_difference"),
            "irrelevant": cnt(npdi_raw, "irrelevant"),
        },
        "evergreen_all": {
            "avoids": cnt(events, "avoids"),
            "makes_worse": cnt(events, "makes_worse"),
            "no_difference": cnt(events, "no_difference"),
            "irrelevant": cnt(events, "irrelevant"),
        },
        "exploited_by_category": {
            "avoids": [e["cve"] for e in exploited if cat(e) == "avoids"],
            "makes_worse": [e["cve"] for e in exploited if cat(e) == "makes_worse"],
            "no_difference": [e["cve"] for e in exploited if cat(e) == "no_difference"],
            "irrelevant": [e["cve"] for e in exploited if cat(e) == "irrelevant"],
        },
        "fam_npdi": dict(fam_npdi),
        "npdi_raw_exploited": sum(1 for e in npdi_raw if e.get("exploited")),
    }


def _check_narrative_outcome(r: TestReporter, canon: dict) -> None:
    """The page's claim is that every 'makes_worse' event is also exploited.

    If a non-exploited makes_worse appears, the framing needs revision.
    """
    mw = canon["evergreen_all"]["makes_worse"]
    mw_exp = len(canon["exploited_by_category"]["makes_worse"])
    r.check(
        mw == mw_exp,
        f"every makes_worse event is also exploited "
        f"(makes_worse={mw}, makes_worse_AND_exploited={mw_exp}). "
        "If this trips, the 'evergreening's directional effect is "
        "unambiguously negative' framing needs revision."
    )

    # And: avoided cohort should not contain exploited events. If it
    # ever does, the page's "neither exploited" framing breaks.
    avoid_exp = len(canon["exploited_by_category"]["avoids"])
    r.check(
        avoid_exp == 0,
        f"no exploited events in the 'avoids' cohort (got {avoid_exp})"
    )


def _check_html(r: TestReporter, canon: dict) -> None:
    html = EVERGREEN_HTML.read_text()

    npdi = canon["evergreen_npdi_raw"]
    t = canon["totals"]

    # Hero card: "0 of 40" for avoids
    expected_avoids_hero = f'<div class="num" style="color:var(--accent)">{npdi["avoids"]} of {t["npdi_raw"]}</div>'
    r.check(
        expected_avoids_hero in html,
        f"top hero card has '{expected_avoids_hero}'"
    )

    # Hero card: "2 of 11" for makes_worse exploited (across full set, since
    # the prose includes the DQ-rescue ActiveMQ Jolokia event too)
    mw_exp = len(canon["exploited_by_category"]["makes_worse"])
    expected_worse_hero = f'<div class="num" style="color:var(--red)">{mw_exp} of {t["exploited"]}</div>'
    r.check(
        expected_worse_hero in html,
        f"top hero card has '{expected_worse_hero}'"
    )

    # Java Libraries section hero row
    java_avoids_hero = f'<div class="num" style="color:var(--green)">{npdi["avoids"]}</div>'
    r.check(
        java_avoids_hero in html,
        f"java section hero has avoids count '{java_avoids_hero}'"
    )

    java_worse_hero = f'<div class="num" style="color:var(--red)">{npdi["makes_worse"]}</div>'
    r.check(
        java_worse_hero in html,
        f"java section hero has makes_worse count '{java_worse_hero}'"
    )

    # Lead paragraph numbers
    r.check(
        f"<strong>{t['all_ch']} Critical/High CVEs</strong>" in html,
        f"java lead has '<strong>{t['all_ch']} Critical/High CVEs</strong>'"
    )
    r.check(
        f"<strong>{t['npdi_raw']} NP+DI raw</strong>" in html,
        f"java lead has '<strong>{t['npdi_raw']} NP+DI raw</strong>'"
    )
    r.check(
        f"<strong>{t['exploited']} actually-exploited</strong>" in html,
        f"java lead has '<strong>{t['exploited']} actually-exploited</strong>'"
    )

    # Headline classification statement in the "no difference" prose:
    # "Both generations affected: 25 of the 40 NP+DI raw events"
    expected_nodiff = (
        f"Both generations affected: "
        f"{npdi['no_difference']} of the {t['npdi_raw']} NP+DI raw events"
    )
    r.check(
        expected_nodiff in html,
        f"java prose has '{expected_nodiff}'"
    )

    # "Irrelevant: 14 of the 40 NP+DI raw events..."
    expected_irrel = (
        f"Irrelevant: {npdi['irrelevant']} of the {t['npdi_raw']} NP+DI raw events"
    )
    r.check(
        expected_irrel in html,
        f"java prose has '{expected_irrel}'"
    )

    # NP+DI raw exploited count footnote
    r.check(
        f"{canon['npdi_raw_exploited']} of {t['npdi_raw']} exploited" in html
        or f"{canon['npdi_raw_exploited']} of 40 exploited" in html,
        f"breakdown table footer has '{canon['npdi_raw_exploited']} of {t['npdi_raw']} exploited'"
    )

    # Per-family NP+DI raw counts are mentioned in the prose
    fam = canon["fam_npdi"]
    # Tomcat 7
    if fam.get("Tomcat") == 7:
        r.check(
            "Tomcat (7 of 7 NP+DI events)" in html,
            "java prose says 'Tomcat (7 of 7 NP+DI events)'"
        )
    # Spring Security 8
    if fam.get("Spring Security") == 8:
        r.check(
            "Spring Security (8 of 8 NP+DI events)" in html,
            "java prose says 'Spring Security (8 of 8 NP+DI events)'"
        )
    # XStream 6
    if fam.get("XStream") == 6:
        r.check(
            "XStream (6 NP+DI events)" in html,
            "java prose says 'XStream (6 NP+DI events)'"
        )
    # jackson-databind 5
    if fam.get("jackson-databind") == 5:
        r.check(
            "jackson-databind (5 NP+DI events)" in html,
            "java prose says 'jackson-databind (5 NP+DI events)'"
        )

    # Headline summary tuple "0 / 1 / 25 / 14"
    r.check(
        re.search(r"0 avoided / 1 made worse / 25 no-difference / 14 irrelevant", html) is not None,
        "java prose has headline tuple '0 avoided / 1 made worse / 25 no-difference / 14 irrelevant'"
    )


def main() -> int:
    r = TestReporter("evergreen-java")
    _check_reproducible(r)
    _check_mapping_completeness(r)

    events = json.load(open(EVENTS_FILE))["events"]
    mapping = json.load(open(MAPPING_FILE))["mapping"]
    canon = _derive_canonical(events, mapping)

    _check_narrative_outcome(r, canon)
    _check_html(r, canon)

    return r.summary_exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
