#!/usr/bin/env python3
"""
Verify the §15 EPSS-marginal claims on docs/periodicity.html match
data/epss-marginal.json (the reproducible artifact produced by
scripts/compute_epss_marginal.py).

The published §15 narrative quotes:
  - Hacker S+A row: 7/8 caught, 11 patch events
  - Marginal-on-model table for EPSS >= 0.10 and >= 0.50

If those numbers drift out of sync with the JSON, this test fails fast.
The script is offline-only — it only reads the on-disk JSON; the
data-fetch step (scripts/compute_epss_marginal.py without --check) is
the one that hits the FIRST.org API.

Test does NOT regenerate the dataset (which would require network).
Use `python3 scripts/compute_epss_marginal.py` to refresh the JSON
when EPSS scores have moved enough to change the absorption picture.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
JSON_PATH = REPO / "data" / "epss-marginal.json"
PAGE_PATH = REPO / "docs" / "periodicity.html"


def main() -> int:
    fails = 0

    if not JSON_PATH.exists():
        print(f"FAIL — {JSON_PATH} missing. Run "
              f"`python3 scripts/compute_epss_marginal.py` to generate.")
        return 1

    data = json.load(open(JSON_PATH))
    page = PAGE_PATH.read_text()

    # ---- Hacker S+A row ----
    sa = data["summary"]["hacker_sa_in_scope_8"]
    sa_caught = sa["day_0"]  # e.g. "7/8"
    sa_pe = sa["total_patch_events_on_manifest"]

    # The page row should contain the day_0 / day_7 etc. fraction and the
    # patch event count. We do a lightweight check: confirm the day_0 string
    # appears 4 times (one per Day 0/7/30/Eventually cell) inside a Hacker S+A
    # row, and the patch-event count appears in the same row.
    sa_row_match = re.search(
        r"<td><strong>Hacker S\+A</strong></td>"
        r"\s*<td><strong>(\d/8)</strong></td>\s*<td><strong>(\d/8)</strong></td>"
        r"\s*<td><strong>(\d/8)</strong></td>\s*<td><strong>(\d/8)</strong></td>"
        r"\s*<td><strong>(\d+)</strong></td>",
        page, re.DOTALL,
    )
    if not sa_row_match:
        fails += 1
        print(f"FAIL — could not locate Hacker S+A row in §15 EPSS table")
    else:
        d0, d7, d30, ev, pe = sa_row_match.groups()
        for label, value in [("Day 0", d0), ("Day 7", d7),
                              ("Day 30", d30), ("Eventually", ev)]:
            if value != sa_caught:
                fails += 1
                print(f"FAIL — Hacker S+A {label} on page = {value} "
                      f"but JSON says {sa_caught}")
        if int(pe) != sa_pe:
            fails += 1
            print(f"FAIL — Hacker S+A patch events on page = {pe} "
                  f"but JSON says {sa_pe}")

    # ---- Marginal numbers for both thresholds ----
    # Page row pattern (one row per threshold):
    #   <td>EPSS ≥ 0.10</td><td>33 patch events</td>
    #   <td><strong>{N}</strong> patch events <span ...>({absorbed_count}/{N_cves} ...)</span></td>
    #   ... (3 such cells: NP+DI, NP+DI+DQ, Hacker S+A)
    for thr_label, thr_key in [("0.10", "epss_ge_10"), ("0.50", "epss_ge_50")]:
        s = data["summary"][thr_key]
        # Find the marginal-table row in the page. Row layout:
        #   <tr><td>EPSS ≥ 0.10</td><td>33 patch events</td>
        #   <td><strong>5</strong> patch events <span ...>(85/90 ...)</span></td>
        #   <td><strong>3</strong> ...</td><td><strong>7</strong> ...</td></tr>
        row_pat = re.compile(
            r"<tr><td>EPSS ≥ " + re.escape(thr_label) + r"</td>"
            r"<td>(\d+) patch events</td>"
            r"<td><strong>(\d+)</strong> patch events.*?</td>"
            r"<td><strong>(\d+)</strong> patch events.*?</td>"
            r"<td><strong>(\d+)</strong> patch events.*?</td>",
            re.DOTALL,
        )
        m = row_pat.search(page)
        if not m:
            fails += 1
            print(f"FAIL — could not locate marginal row for EPSS >= {thr_label}")
            continue
        standalone, np_di_pe, np_di_dq_pe, hacker_pe = m.groups()

        # Compare to JSON
        expected = {
            "NP+DI": s["marginal"]["NP+DI"]["marginal_patch_events"],
            "NP+DI+DQ": s["marginal"]["NP+DI+DQ"]["marginal_patch_events"],
            "Hacker S+A": s["marginal"]["Hacker S+A"]["marginal_patch_events"],
        }
        page_vals = {
            "NP+DI": int(np_di_pe),
            "NP+DI+DQ": int(np_di_dq_pe),
            "Hacker S+A": int(hacker_pe),
        }
        for model in expected:
            if expected[model] != page_vals[model]:
                fails += 1
                print(f"FAIL — EPSS >= {thr_label} marginal to {model}: "
                      f"page = {page_vals[model]}, JSON = {expected[model]}")

    # ---- Structural sanity on the JSON itself ----
    for thr_key in ("epss_ge_10", "epss_ge_50"):
        s = data["summary"][thr_key]
        for model in ("NP+DI", "NP+DI+DQ", "Hacker S+A"):
            m = s["marginal"][model]
            if m["marginal_cves"] + m["absorbed_cves"] != s["standalone_raw_cves"]:
                fails += 1
                print(f"FAIL — {thr_key} {model}: marginal+absorbed != standalone")

    # ---- Timing comparison headline (avg days faster + caught-before-exploit) ----
    tc = data["summary"].get("timing_comparison")
    if tc is None:
        fails += 1
        print("FAIL — summary.timing_comparison missing from JSON")
    else:
        # Page placeholders use rounded-to-1-decimal averages
        avg10 = tc["avg_days_faster_vs_epss_10"]
        avg50 = tc["avg_days_faster_vs_epss_50"]
        cbe = tc["caught_before_exploit"]

        page_avg10 = re.search(
            r"<span data-epss-avg-d10>([0-9.]+)</span>", page,
        )
        page_avg50 = re.search(
            r"<span data-epss-avg-d50>([0-9.]+)</span>", page,
        )
        page_y_model = re.search(
            r"<span data-epss-y-model>(\d+)</span>", page,
        )
        page_y_e10 = re.search(
            r"<span data-epss-y-e10>(\d+)</span>", page,
        )
        page_y_e50 = re.search(
            r"<span data-epss-y-e50>(\d+)</span>", page,
        )
        page_marg10 = re.search(
            r"<span data-epss-marginal-10>(\d+)</span>", page,
        )
        page_marg50 = re.search(
            r"<span data-epss-marginal-50>(\d+)</span>", page,
        )

        # Avg days faster — page rounds to 1 decimal; tolerate ±0.05 for rounding.
        for label, page_match, json_val in [
            ("avg_days_faster_vs_epss_10", page_avg10, avg10),
            ("avg_days_faster_vs_epss_50", page_avg50, avg50),
        ]:
            if page_match is None:
                fails += 1
                print(f"FAIL — page placeholder for {label} not found")
                continue
            page_val = float(page_match.group(1))
            if abs(page_val - json_val) > 0.05:
                fails += 1
                print(f"FAIL — page {label} = {page_val} but JSON = {json_val:.4f}")

        # Caught-before-exploit fractions (model = "Y/8")
        def parse_y(frac: str) -> int:
            return int(frac.split("/")[0])

        for label, page_match, expected in [
            ("y_model", page_y_model, parse_y(cbe["model"])),
            ("y_epss10", page_y_e10, parse_y(cbe["epss_ge_10"])),
            ("y_epss50", page_y_e50, parse_y(cbe["epss_ge_50"])),
            ("marginal_10", page_marg10, cbe["marginal_model_minus_epss_10"]),
            ("marginal_50", page_marg50, cbe["marginal_model_minus_epss_50"]),
        ]:
            if page_match is None:
                fails += 1
                print(f"FAIL — page placeholder for {label} not found")
                continue
            page_val = int(page_match.group(1))
            if page_val != expected:
                fails += 1
                print(f"FAIL — page {label} = {page_val} but JSON = {expected}")

        # Cohort-size sanity
        if tc["cohort_size"] != 8:
            fails += 1
            print(f"FAIL — timing_comparison.cohort_size = {tc['cohort_size']}, expected 8")
        # Per-CVE rows sum should match cohort_size
        if len(tc["per_cve"]) != tc["cohort_size"]:
            fails += 1
            print(f"FAIL — timing_comparison.per_cve has {len(tc['per_cve'])} rows, "
                  f"expected {tc['cohort_size']}")
        # Pre-EPSS handling: avg_n_with_epss_coverage = cohort_size - len(pre_epss_cves)
        expected_n = tc["cohort_size"] - len(tc["pre_epss_cves"])
        if tc["avg_n_with_epss_coverage"] != expected_n:
            fails += 1
            print(f"FAIL — avg_n_with_epss_coverage = {tc['avg_n_with_epss_coverage']}, "
                  f"expected {expected_n}")

    if fails:
        print(f"\n[epss-marginal] {fails} FAILED")
        return 1
    print(f"[epss-marginal] OK — page §15 numbers match data/epss-marginal.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
