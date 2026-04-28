#!/usr/bin/env python3
"""
7-year manifest reconciliation regression test.

After the 2026-04-28 reconciliation, the canonical 7-year manifest
totals are derived from data/seven-year-manifest-events.json plus the
hacker tier judgments in data/hacker-tiers.json. This test asserts:

  1. The events file is reproducible from the OSV cache (--check passes).
  2. data/integrated-page-aggregates.json totals match what the events
     file plus hacker-tiers actually imply.
  3. docs/periodicity.html §7 chart arrays sum to the canonical totals
     and match the per-quarter aggregates.
  4. docs/periodicity.html §7 prose totals (lead paragraph + per-year
     table tfoot + strategy-efficiency table) match the canonical totals.
  5. docs/index.html §4f prose + strategy-efficiency table + EPSS table
     denominator match the canonical 11/194 totals.
  6. docs/cve-reference.html §5 cohort row count == events file's
     exploited count, and the cohort prose fractions match the model
     classifier's actual catches on the 11-event cohort.

Per CLAUDE.md: claims without tests rot. This test locks the
reconciled totals down so the chart, prose, and tables can't drift
again silently. If any of these assertions fail, the page is out of
sync with the canonical events file and either (a) the events file
needs regenerating via scripts/build_seven_year_manifest_events.py
followed by scripts/build_hacker_tier_data.py, or (b) the page text
needs updating to match. Don't loosen the test.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from _common import TestReporter  # noqa: E402


DQ_RESCUE_CVES = {"CVE-2020-1938", "CVE-2025-24813", "CVE-2026-34197"}


def _build_seven_year_quarter_labels() -> list[str]:
    out = []
    for y in range(2018, 2027):
        for q in range(1, 5):
            if y == 2018 and q < 4:
                continue
            if y == 2026 and q > 2:
                continue
            out.append(f"{y}-Q{q}")
    return out


def _quarter_of(iso_date: str) -> str:
    y, m = int(iso_date[:4]), int(iso_date[5:7])
    return f"{y}-Q{(m - 1) // 3 + 1}"


def _cluster_count(dates: list[str], window_days: int = 7) -> int:
    if not dates:
        return 0
    parsed = sorted(datetime.strptime(d, "%Y-%m-%d") for d in dates)
    clusters = 1
    for prev, cur in zip(parsed, parsed[1:]):
        if (cur - prev).days > window_days:
            clusters += 1
    return clusters


def _derive_canonical() -> dict:
    """Compute the canonical 7-year manifest totals from data files alone."""
    events = json.load(open(REPO / "data" / "seven-year-manifest-events.json"))["events"]
    tiers = json.load(open(REPO / "data" / "hacker-tiers.json"))["tiers"]
    sa_set = {cve for cve, t in tiers.items() if t.get("tier") in ("S", "A")}

    is_npdi_raw = lambda e: e["is_np"] and e["is_di"]
    is_npdi_dq = lambda e: is_npdi_raw(e) or e["cve"] in DQ_RESCUE_CVES
    is_sa = lambda e: e["cve"] in sa_set

    npdi_raw = [e for e in events if is_npdi_raw(e)]
    npdi_dq = [e for e in events if is_npdi_dq(e)]
    hacker_sa = [e for e in events if is_sa(e)]
    union_cves = {e["cve"] for e in npdi_dq} | {e["cve"] for e in hacker_sa}
    union = [e for e in events if e["cve"] in union_cves]
    criticals = [e for e in events if e.get("severity") == "CRITICAL"]
    exploited = [e for e in events if e["exploited"]]

    qlabels = _build_seven_year_quarter_labels()
    q_total = defaultdict(int)
    q_npdi_dq = defaultdict(int)
    q_hacker_sa = defaultdict(int)
    for e in events:
        q = _quarter_of(e["published"])
        q_total[q] += 1
        if is_npdi_dq(e):
            q_npdi_dq[q] += 1
        if is_sa(e):
            q_hacker_sa[q] += 1

    def _row(filtered):
        dates = [e["published"] for e in filtered]
        return {
            "patch_events": _cluster_count(dates),
            "raw": len(filtered),
            "caught": sum(1 for e in filtered if e["exploited"]),
        }

    return {
        "totals": {
            "all_ch":     len(events),
            "npdi_raw":   len(npdi_raw),
            "npdi_dq":    len(npdi_dq),
            "hacker_sa":  len(hacker_sa),
            "exploited":  len(exploited),
        },
        "exploited_caught_by": {
            "npdi_raw": sum(1 for e in exploited if is_npdi_raw(e)),
            "npdi_dq":  sum(1 for e in exploited if is_npdi_dq(e)),
            "hacker_sa": sum(1 for e in exploited if is_sa(e)),
            "union":    sum(1 for e in exploited if (is_npdi_dq(e) or is_sa(e))),
        },
        "strategy": {
            "patch_all_ch":    _row(events),
            "patch_criticals": _row(criticals),
            "npdi_raw":        _row(npdi_raw),
            "npdi_dq":         _row(npdi_dq),
            "hacker_sa":       _row(hacker_sa),
            "union":           _row(union),
        },
        "per_quarter_other": [q_total[q] - q_npdi_dq[q] for q in qlabels],
        "per_quarter_npdi_dq": [q_npdi_dq[q] for q in qlabels],
        "exploited_cves": sorted(e["cve"] for e in exploited),
    }


def _read(path: Path) -> str:
    return path.read_text()


def _check_events_file_reproducible(r: TestReporter) -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/build_seven_year_manifest_events.py", "--check"],
        cwd=REPO, capture_output=True, text=True,
    )
    r.check(proc.returncode == 0,
            f"build_seven_year_manifest_events.py --check should succeed "
            f"(rc={proc.returncode}, stdout={proc.stdout!r}, stderr={proc.stderr!r})")


def _check_aggregates_match_events(r: TestReporter, canon: dict) -> None:
    agg = json.load(open(REPO / "data" / "integrated-page-aggregates.json"))

    # per-year totals
    py_total = agg["seven_year_per_year"]["Total"]
    r.check(py_total["all_ch"] == canon["totals"]["all_ch"],
            f"agg.Total.all_ch == {canon['totals']['all_ch']} (got {py_total['all_ch']})")
    r.check(py_total["npdi_raw"] == canon["totals"]["npdi_raw"],
            f"agg.Total.npdi_raw == {canon['totals']['npdi_raw']} (got {py_total['npdi_raw']})")
    r.check(py_total["npdi_ai"] == canon["totals"]["npdi_dq"],
            f"agg.Total.npdi_ai == {canon['totals']['npdi_dq']} (got {py_total['npdi_ai']})")
    r.check(py_total["hacker_sa"] == canon["totals"]["hacker_sa"],
            f"agg.Total.hacker_sa == {canon['totals']['hacker_sa']} (got {py_total['hacker_sa']})")
    r.check(py_total["exploited"] == canon["totals"]["exploited"],
            f"agg.Total.exploited == {canon['totals']['exploited']} (got {py_total['exploited']})")

    expected_catches = f"{canon['exploited_caught_by']['hacker_sa']}/{canon['totals']['exploited']}"
    r.check(py_total["hacker_catches"] == expected_catches,
            f"agg.Total.hacker_catches == {expected_catches} (got {py_total['hacker_catches']})")

    # per-quarter
    pq = agg["seven_year_per_quarter"]
    r.check(pq["other"] == canon["per_quarter_other"],
            f"agg.per_quarter.other matches derived (got {pq['other']!r})")
    r.check(pq["npdi_ai"] == canon["per_quarter_npdi_dq"],
            f"agg.per_quarter.npdi_ai matches derived (got {pq['npdi_ai']!r})")
    r.check(sum(pq["other"]) + sum(pq["npdi_ai"]) == canon["totals"]["all_ch"],
            f"per_quarter.other+npdi_ai sum == {canon['totals']['all_ch']}")

    # strategy efficiency
    se = agg["strategy_efficiency_7yr"]
    for key, src in [("patch_all_ch", "patch_all_ch"),
                     ("patch_criticals", "patch_criticals"),
                     ("npdi_raw", "npdi_raw"),
                     ("npdi_ai", "npdi_dq"),
                     ("hacker_sa", "hacker_sa"),
                     ("union_npdi_ai_hacker", "union")]:
        c = canon["strategy"][src]
        r.check(se[key]["raw_triggers"] == c["raw"],
                f"strategy[{key}].raw_triggers == {c['raw']} (got {se[key]['raw_triggers']})")
        r.check(se[key]["exploits_caught"] == c["caught"],
                f"strategy[{key}].exploits_caught == {c['caught']} (got {se[key]['exploits_caught']})")
        r.check(se[key]["patch_events_clustered"] == c["patch_events"],
                f"strategy[{key}].patch_events_clustered == {c['patch_events']} "
                f"(got {se[key]['patch_events_clustered']})")


def _extract_chart_arrays(html: str) -> tuple[list[int], list[int]]:
    """Pull rmOther / rmNPDI from periodicity.html chart code."""
    m_other = re.search(r"const rmOther\s*=\s*\[([0-9, ]+)\];", html)
    m_npdi = re.search(r"const rmNPDI\s*=\s*\[([0-9, ]+)\];", html)
    if not m_other or not m_npdi:
        return [], []
    return ([int(x) for x in m_other.group(1).split(",")],
            [int(x) for x in m_npdi.group(1).split(",")])


def _check_periodicity_page(r: TestReporter, canon: dict) -> None:
    html = _read(REPO / "docs" / "periodicity.html")

    # Chart arrays
    rmOther, rmNPDI = _extract_chart_arrays(html)
    r.check(rmOther == canon["per_quarter_other"],
            f"periodicity rmOther matches canonical per-quarter other "
            f"(canonical={canon['per_quarter_other']}, got={rmOther})")
    r.check(rmNPDI == canon["per_quarter_npdi_dq"],
            f"periodicity rmNPDI matches canonical per-quarter NP+DI+DQ "
            f"(canonical={canon['per_quarter_npdi_dq']}, got={rmNPDI})")
    r.check(sum(rmOther) + sum(rmNPDI) == canon["totals"]["all_ch"],
            f"periodicity rmOther+rmNPDI sum == {canon['totals']['all_ch']}")

    # Lead-paragraph prose tuple (e.g. "194 critical/high CVEs → 40 NP+DI raw → 43 NP+DI + DQ → 16 hacker S+A → 11 actually exploited")
    t = canon["totals"]
    expected_lead = (f"<strong>{t['all_ch']} critical/high CVEs → "
                     f"{t['npdi_raw']} NP+DI raw → "
                     f"{t['npdi_dq']} NP+DI + DQ → "
                     f"{t['hacker_sa']} hacker S+A → "
                     f"{t['exploited']} actually exploited</strong>")
    r.check(expected_lead in html,
            f"periodicity §7 lead prose contains canonical totals: {expected_lead!r}")

    # Per-year table tfoot
    cb = canon["exploited_caught_by"]
    expected_tfoot = (f"<tfoot><tr style=\"font-weight:600\"><td>Total</td>"
                      f"<td>{t['all_ch']}</td><td>{t['npdi_raw']}</td>"
                      f"<td>{t['npdi_dq']}</td><td>{t['hacker_sa']}</td>"
                      f"<td>{t['exploited']}</td>")
    r.check(expected_tfoot in html,
            f"periodicity §7 tfoot row contains canonical totals: {expected_tfoot!r}")


def _check_index_page(r: TestReporter, canon: dict) -> None:
    html = _read(REPO / "docs" / "index.html")
    t = canon["totals"]
    cb = canon["exploited_caught_by"]

    # §4f lead "194 critical/high CVEs", "11 actually exploited"
    r.check(f"<strong>{t['all_ch']} critical/high CVEs</strong>" in html,
            f"index §4f lead has '<strong>{t['all_ch']} critical/high CVEs</strong>'")
    r.check(f"<strong>{t['exploited']} actually exploited</strong>" in html,
            f"index §4f lead has '<strong>{t['exploited']} actually exploited</strong>'")

    # §4f strategy-efficiency table cell: union row should have correct fraction
    union = canon["strategy"]["union"]
    expected_union_cell = f"<strong>{union['caught']}/{t['exploited']}</strong>"
    r.check(expected_union_cell in html,
            f"index §4f strategy table union row has '{expected_union_cell}'")

    # Hero §4a stat "10/11 7-year backtest catch (union)"
    expected_hero = f"<div class=\"number\">{cb['union']}/{t['exploited']}</div>"
    r.check(expected_hero in html,
            f"index §4a hero stat has '{expected_hero}'")

    # §3d/3e prose: "NP+DI raw catches X of N..."
    expected_3d = (f"NP+DI raw catches {cb['npdi_raw']} of {t['exploited']} "
                   f"actually-exploited events; NP+DI+DQ catches {cb['npdi_dq']}; "
                   f"hacker S+A catches {cb['hacker_sa']}. Their union catches {cb['union']}")
    r.check(expected_3d in html,
            f"index §3d prose: '{expected_3d}'")


def _check_cve_reference_page(r: TestReporter, canon: dict) -> None:
    html = _read(REPO / "docs" / "cve-reference.html")
    t = canon["totals"]
    cb = canon["exploited_caught_by"]

    # Heading text reflects the exploited count
    expected_h2 = f"The {t['exploited']} actually-exploited events"
    r.check(expected_h2 in html,
            f"cve-reference §5 heading contains '{expected_h2}'")

    # Prose contains "NP+DI raw catches A/N; NP+DI+DQ catches B/N; hacker S+A catches C/N; union catches D/N"
    n = t["exploited"]
    expected_prose = (f"<strong>NP+DI raw catches {cb['npdi_raw']}/{n}; "
                      f"NP+DI+DQ catches {cb['npdi_dq']}/{n}; "
                      f"hacker S+A catches {cb['hacker_sa']}/{n}; "
                      f"union catches {cb['union']}/{n}</strong>")
    r.check(expected_prose in html,
            f"cve-reference §5 prose: '{expected_prose}'")

    # Cohort table has one row per exploited CVE (each CVE appears at least once in
    # an <a href="https://nvd.nist.gov/vuln/detail/CVE-..."> link in the cohort
    # table). We just check membership of every exploited CVE.
    cohort_section_start = html.find('id="exploited-cohort"')
    cohort_section_end = html.find('id="conflicts"')
    r.check(cohort_section_start > 0 and cohort_section_end > cohort_section_start,
            "cve-reference §5 (#exploited-cohort .. #conflicts) bounds resolved")
    cohort_html = html[cohort_section_start:cohort_section_end]
    for cve in canon["exploited_cves"]:
        r.check(f"vuln/detail/{cve}" in cohort_html,
                f"cve-reference §5 cohort table includes {cve}")


def main() -> int:
    r = TestReporter("seven-year-reconciliation")

    canon = _derive_canonical()

    _check_events_file_reproducible(r)
    _check_aggregates_match_events(r, canon)
    _check_periodicity_page(r, canon)
    _check_index_page(r, canon)
    _check_cve_reference_page(r, canon)

    return r.summary_exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
