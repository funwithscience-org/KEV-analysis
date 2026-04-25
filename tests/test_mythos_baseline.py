#!/usr/bin/env python3
"""
Verify the Mythos chart values on docs/glasswing.html match the canonical
config.json baseline_data fields.

Per the prior AI's Q9 answer:
  - config.json is authoritative for both NVD monthly volume and KEV monthly
    additions
  - The refresh agent updates config.json daily and writes the same values
    into the HTML chart arrays (mActualCve, mKevLookup)
  - Monthly KEV adds are exact integer counts (verifiable equality)
  - Monthly NVD CVE counts can have an extrapolation gap for the current
    (partial) month — config has MTD actual, HTML may have extrapolated
    full-month estimate

Test invariants:
  1. KEV chart values exactly match config.json kev_monthly_2026
  2. NVD chart values exactly match config.json monthly_cve_2026 for
     completed months (not the latest one which may be extrapolated)
  3. The chart arrays cover the months listed in config
  4. Monthly counts are non-negative

Source-of-truth flow:
    NVD/KEV API → refresh agent → config.json → glasswing.html chart arrays
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def extract_js_dict(html: str, var_name: str) -> dict[str, int]:
    """Pull a JS dict literal like {"2025-01":4200, ...} from the HTML."""
    m = re.search(rf'const\s+{var_name}\s*=\s*\{{([^}}]+)\}}', html)
    if not m:
        return {}
    out = {}
    for kv in re.finditer(r'"([^"]+)"\s*:\s*(\d+)', m.group(1)):
        out[kv.group(1)] = int(kv.group(2))
    return out


def main() -> int:
    fails = 0

    config = json.load(open(REPO / "config.json"))
    baseline = config.get("baseline_data", {})
    cfg_cve = baseline.get("monthly_cve_2026", {})
    cfg_kev = baseline.get("kev_monthly_2026", {})

    glasswing_html = (REPO / "docs" / "glasswing.html").read_text()
    chart_cve = extract_js_dict(glasswing_html, "mActualCve")
    chart_kev = extract_js_dict(glasswing_html, "mKevLookup")

    if not chart_cve:
        fails += 1
        print("FAIL — could not extract mActualCve from glasswing.html")
    if not chart_kev:
        fails += 1
        print("FAIL — could not extract mKevLookup from glasswing.html")

    # 1. KEV chart values exactly match config for every month config tracks
    for month, expected in sorted(cfg_kev.items()):
        actual = chart_kev.get(month)
        if actual != expected:
            fails += 1
            print(f"FAIL — chart mKevLookup[{month}]={actual} != "
                  f"config.kev_monthly_2026[{month}]={expected}")

    # 2. NVD chart values match config for completed months. The latest
    #    month in config may have an MTD value that's lower than the chart's
    #    extrapolation.
    if cfg_cve:
        sorted_months = sorted(cfg_cve.keys())
        latest = sorted_months[-1]
        for month in sorted_months:
            cfg_val = cfg_cve[month]
            chart_val = chart_cve.get(month)
            if chart_val is None:
                fails += 1
                print(f"FAIL — chart mActualCve missing month {month}")
                continue
            if month == latest:
                # Allow chart >= config (extrapolation upward)
                if chart_val < cfg_val:
                    fails += 1
                    print(f"FAIL — chart mActualCve[{latest}]={chart_val} < "
                          f"config MTD {cfg_val}; should be >= MTD")
                if chart_val > cfg_val * 2:
                    fails += 1
                    print(f"FAIL — chart mActualCve[{latest}]={chart_val} more "
                          f"than 2x config MTD {cfg_val}; extrapolation looks wrong")
            else:
                if chart_val != cfg_val:
                    fails += 1
                    print(f"FAIL — chart mActualCve[{month}]={chart_val} != "
                          f"config monthly_cve_2026[{month}]={cfg_val} "
                          f"(completed month, should be exact)")

    # 3. Non-negative counts everywhere
    for month, val in chart_cve.items():
        if val < 0:
            fails += 1
            print(f"FAIL — chart mActualCve[{month}]={val} is negative")
    for month, val in chart_kev.items():
        if val < 0:
            fails += 1
            print(f"FAIL — chart mKevLookup[{month}]={val} is negative")

    if fails:
        print(f"\n[mythos-baseline] {fails} FAILED")
        return 1
    print(f"[mythos-baseline] OK — chart values match config.json baseline_data "
          f"({len(cfg_kev)} KEV months, {len(cfg_cve)} CVE months tracked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
