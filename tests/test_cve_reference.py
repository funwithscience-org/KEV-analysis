#!/usr/bin/env python3
"""
Numeric/drift regression tests for the per-CVE reference page.

Guards:
  - scripts/build_cve_reference.py runs without error
  - data/cve-reference.json matches what would be regenerated (drift)
  - Inline DATA blob in docs/cve-reference.html matches the JSON
  - All CVEs in source artifacts appear in the union (no silent drops)
  - Canonical anchor CVEs are present
  - No duplicate CVEs in the output
  - Source-artifact contribution counts roughly track the inputs
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

from _common import TestReporter  # noqa: E402

DATA = REPO / "data"
DOCS = REPO / "docs"
SCRIPT = REPO / "scripts" / "build_cve_reference.py"
JSON_OUT = DATA / "cve-reference.json"
HTML_OUT = DOCS / "cve-reference.html"

CANONICAL_ANCHORS = [
    "CVE-2021-44228",   # Log4Shell
    "CVE-2022-22965",   # Spring4Shell
    "CVE-2017-12615",   # Tomcat HTTP PUT
    "CVE-2017-12617",   # Tomcat HTTP PUT (Win)
    "CVE-2026-1340",    # Ivanti EPMM (canonical anchor for edge-appliance auth-bypass + RCE)
    "CVE-2020-1938",    # Ghostcat
]


_HTML_DATA_BLOCK_RE = re.compile(
    r'<script id="cveReferenceData" type="application/json">(.*?)</script>',
    re.DOTALL,
)


def _norm_cve(s: str | None) -> str | None:
    if not s or not isinstance(s, str):
        return None
    s = s.strip().upper()
    return s if s.startswith("CVE-") else None


def _extract_cve_set_from_artifact(path: Path) -> set[str]:
    """Pull CVE IDs out of any artifact in data/, regardless of shape.
    Tolerant: walks the whole tree and collects strings that look like
    CVE IDs."""
    if not path.exists():
        return set()
    out: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and (k == "cve" or k == "anchor_cve"):
                    n = _norm_cve(v)
                    if n:
                        out.add(n)
                elif isinstance(v, dict):
                    # tiers/{cve}: {...} pattern in hacker-tiers.json
                    for k2 in v:
                        if isinstance(k2, str):
                            n = _norm_cve(k2)
                            if n:
                                out.add(n)
                    walk(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    with open(path) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return out
    walk(data)
    # tiers / events keyed by CVE — additional sweep
    return out


def _config_watch_list_cves() -> set[str]:
    cfg_path = REPO / "config.json"
    if not cfg_path.exists():
        return set()
    out = set()
    cfg = json.loads(cfg_path.read_text())
    for cat in ("server", "desktop"):
        for w in (cfg.get("exploit_watch_list", {}) or {}).get(cat, []) or []:
            n = _norm_cve(w.get("cve"))
            if n:
                out.add(n)
    return out


def main() -> int:
    r = TestReporter("cve-reference")

    # 1. Script runs without error
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--check"],
        capture_output=True, text=True, cwd=str(REPO),
    )
    r.check(proc.returncode == 0,
            f"build_cve_reference.py --check exited {proc.returncode}: {proc.stdout}{proc.stderr}")

    # 2. JSON exists and parses
    r.check(JSON_OUT.exists(), f"{JSON_OUT.name} should exist")
    if JSON_OUT.exists():
        try:
            payload = json.loads(JSON_OUT.read_text())
        except json.JSONDecodeError as e:
            r.check(False, f"{JSON_OUT.name} not valid JSON: {e}")
            return r.summary_exit_code()
    else:
        return r.summary_exit_code()

    # 3. Schema essentials
    r.check("rows" in payload, "JSON has top-level 'rows'")
    r.check("n_cves" in payload, "JSON has 'n_cves'")
    r.check("source_artifacts" in payload, "JSON has 'source_artifacts'")
    rows = payload.get("rows", [])
    r.check(len(rows) == payload.get("n_cves"),
            f"n_cves {payload.get('n_cves')} matches len(rows) {len(rows)}")

    # 4. Canonical anchors present
    cve_set = {row["cve"] for row in rows}
    for a in CANONICAL_ANCHORS:
        r.check(a in cve_set, f"canonical anchor {a} present in reference")

    # 5. No duplicate CVE IDs
    r.check(len(cve_set) == len(rows),
            f"no duplicate CVEs (saw {len(rows)} rows, {len(cve_set)} unique)")

    # 6. All CVEs in source artifacts roll into the union
    source_files = {
        "retro-model-run-2026-03-27-to-04-26": DATA / "retro-model-run-2026-03-27-to-04-26.json",
        "seven-year-manifest-events":           DATA / "seven-year-manifest-events.json",
        "seven-year-npdi-events":               DATA / "seven-year-npdi-events.json",
        "retro-baseline-april-2022":            DATA / "retro-baseline-april-2022.json",
        "di-reclassification":                  DATA / "di-reclassification.json",
        "doc-canonical-npdi-events":            DATA / "doc-canonical-npdi-events.json",
        "hacker-tiers":                         DATA / "hacker-tiers.json",
        "waf-defensibility":                    DATA / "waf-defensibility.json",
        "legacy-static-rows":                   DATA / "legacy-static-rows.json",
    }
    for name, p in source_files.items():
        if not p.exists():
            continue
        cves = _extract_cve_set_from_artifact(p)
        missing = cves - cve_set
        # Tolerate non-CVE OSV-only IDs that we've already filtered out
        r.check(not missing, f"all CVEs from {name} present in reference; missing: {sorted(missing)[:5]}")

    # Watch list (config.json)
    wl = _config_watch_list_cves()
    missing_wl = wl - cve_set
    r.check(not missing_wl, f"watch-list CVEs all present in reference; missing: {sorted(missing_wl)}")

    # 7. Source artifacts have non-zero contributions
    sa = payload.get("source_artifacts", [])
    r.check(len(sa) >= 5, f"at least 5 source artifacts contributed; got {len(sa)}")
    for s in sa:
        r.check(s.get("rows_contributed", 0) > 0,
                f"source {s.get('artifact')} contributed >0 rows; got {s.get('rows_contributed')}")

    # 7b. Twelve-month per-framework cohorts present and roughly the right size.
    # The doc cites Spring 22, Node 20, Django 18, Netty 3 raw events. The
    # cve-reference cohort counts unique CVEs per framework, so Spring is 20
    # (the cache contains two duplicate vuln_id rows for the 2026-04-15
    # Tomcat pair); the others are unique-equal.
    expected_12m_unique_cves = {
        "twelve-month-spring": 20,
        "twelve-month-nodejs": 20,
        "twelve-month-django": 18,
        "twelve-month-netty": 3,
    }
    sa_by_name = {s["artifact"]: s["rows_contributed"] for s in sa}
    for name, n in expected_12m_unique_cves.items():
        r.check(sa_by_name.get(name) == n,
                f"twelve-month cohort {name} contributed {n} unique CVEs; got {sa_by_name.get(name)}")

    # 7c. Cohort row counts per source artifact (rows whose `sources` includes the artifact)
    # must match what the section table will render. Each section's table is just
    # rows.filter(sources includes srcName), so this guards the section sizes too.
    cohort_sizes = {}
    for row in rows:
        for s in row.get("sources", []):
            cohort_sizes[s] = cohort_sizes.get(s, 0) + 1
    # The rows-contributed counts in the JSON header should equal the per-row tally.
    for s in sa:
        name = s["artifact"]
        tally = cohort_sizes.get(name, 0)
        r.check(tally == s["rows_contributed"],
                f"cohort {name} per-row tally ({tally}) matches rows_contributed ({s['rows_contributed']})")

    # 8. HTML inline DATA matches JSON (count check)
    if HTML_OUT.exists():
        text = HTML_OUT.read_text()
        m = _HTML_DATA_BLOCK_RE.search(text)
        r.check(m is not None, "docs/cve-reference.html has cveReferenceData script tag")
        if m:
            try:
                inline = json.loads(m.group(1))
                r.check(inline.get("n_cves") == payload.get("n_cves"),
                        f"inline n_cves {inline.get('n_cves')} matches JSON n_cves {payload.get('n_cves')}")
                r.check(len(inline.get("rows", [])) == len(rows),
                        f"inline rows length {len(inline.get('rows', []))} matches JSON {len(rows)}")
                inline_cves = {row.get("cve") for row in inline.get("rows", [])}
                for a in CANONICAL_ANCHORS:
                    r.check(a in inline_cves, f"canonical anchor {a} present in inline DATA blob")
            except json.JSONDecodeError as e:
                r.check(False, f"inline DATA blob is not valid JSON: {e}")

    # 9. Every row carries a non-empty sources list
    for row in rows:
        if not row.get("sources"):
            r.check(False, f"row {row.get('cve')} has empty sources")
            break
    else:
        r.check(True, "every row has a non-empty sources list")

    # 10. No row has a hacker_tier outside the canonical set
    valid_tiers = {None, "S", "A", "B", "C", "D"}
    bad_tiers = [r2["cve"] for r2 in rows if r2.get("hacker_tier") not in valid_tiers]
    r.check(not bad_tiers, f"all hacker_tier values are S/A/B/C/D/null; bad: {bad_tiers[:5]}")

    # 11. No row has a combined_verdict outside the canonical set
    valid_verdicts = {None, "triggered", "autobuild", "bau", "out-of-scope"}
    bad_verdicts = [r2["cve"] for r2 in rows if r2.get("combined_verdict") not in valid_verdicts]
    r.check(not bad_verdicts,
            f"all combined_verdict values valid; bad: {bad_verdicts[:5]}")

    return r.summary_exit_code()


if __name__ == "__main__":
    sys.exit(main())
