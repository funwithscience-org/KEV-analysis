#!/usr/bin/env python3
"""
Compute the tte_data field that drives the tteChart on docs/dashboard.html.

Per the prior AI's Q6 answer:
  - For each KEV entry with a 2021+ CVE: TTE = dateAdded - cve_published_date
  - Group by CVE publication year
  - Compute median, p25, p75, mean, n
  - Doc only includes years 2021-2024 because 2025/2026 have insufficient N
    AND right-censoring (recent CVEs that haven't been added to KEV yet
    might still be added later)

Sources:
  data/kev-snapshot-2026-05-01.json       (dateAdded for each KEV entry)
  data/_kev-publication-dates.json        (cached OSV-derived publication dates)

Output: data/tte.json
    {
      methodology: { ... },
      tte_data: [
        {year:2021, n:N, median:M, p25:..., p75:..., mean:...}, ...
      ]
    }
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Years to include in the chart. Per the prior AI: 2025/2026 excluded due to
# insufficient N + right-censoring (CVEs added to KEV after publication —
# recent years are biased low because only the fastest-to-KEV entries are
# in the catalog yet).
INCLUDE_YEARS = [2021, 2022, 2023, 2024]


def parse_date(s: str | None) -> dt.date | None:
    if not s:
        return None
    try:
        return dt.date.fromisoformat(s[:10])
    except (ValueError, TypeError):
        return None


def percentile(sorted_vals: list[int], p: float) -> int:
    """Linear-interpolation percentile (matches numpy default)."""
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return int(sorted_vals[f])
    return int(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))


def build() -> dict:
    snap = json.load(open(REPO / "data" / "kev-snapshot-2026-05-01.json"))
    pub_cache = json.load(open(REPO / "data" / "_kev-publication-dates.json"))

    by_year: dict[int, list[int]] = defaultdict(list)
    coverage: dict[int, int] = defaultdict(int)  # entries per year
    no_pubdate: dict[int, int] = defaultdict(int)

    for v in snap["vulnerabilities"]:
        cve = v.get("cveID", "")
        if not cve.startswith("CVE-"):
            continue
        try:
            year = int(cve.split("-")[1])
        except (IndexError, ValueError):
            continue
        if year not in INCLUDE_YEARS:
            continue
        coverage[year] += 1
        date_added = parse_date(v.get("dateAdded"))
        pub_entry = pub_cache.get(cve, {})
        published = parse_date(pub_entry.get("published"))
        if not (date_added and published):
            no_pubdate[year] += 1
            continue
        tte_days = (date_added - published).days
        if tte_days < 0:
            # Anomaly — KEV added before publication date (data error). Skip.
            continue
        by_year[year].append(tte_days)

    tte_data = []
    for year in INCLUDE_YEARS:
        vals = sorted(by_year.get(year, []))
        if not vals:
            continue
        tte_data.append({
            "year": year,
            "n": len(vals),
            "median": percentile(vals, 0.50),
            "p25":    percentile(vals, 0.25),
            "p75":    percentile(vals, 0.75),
            "mean":   round(statistics.mean(vals)),
        })

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Time-to-exploit per CVE-publication year, backing the tteChart "
            "on docs/dashboard.html. TTE = dateAdded (CISA KEV) - "
            "cve_published_date (NVD/OSV)."
        ),
        "methodology": {
            "kev_source": "data/kev-snapshot-2026-05-01.json",
            "publication_date_source": "data/_kev-publication-dates.json (OSV)",
            "include_years": INCLUDE_YEARS,
            "exclusion_rationale": (
                "2025/2026 excluded due to insufficient N and right-"
                "censoring — recently-published CVEs that haven't been "
                "added to KEV yet might still be added later, biasing "
                "current-year medians artificially low."
            ),
            "negative_tte_skipped": "rare data anomalies where dateAdded < published",
        },
        "summary": {
            "coverage_per_year": dict(coverage),
            "missing_pubdate_per_year": dict(no_pubdate),
            "total_with_tte": sum(d["n"] for d in tte_data),
        },
        "tte_data": tte_data,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "tte.json"
    new = build()

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("tte_data", "methodology", "summary", "description"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    print(f"wrote {out_path.relative_to(REPO)}")
    s = new["summary"]
    print(f"  coverage per year: {s['coverage_per_year']}")
    print(f"  missing pubdate:   {s['missing_pubdate_per_year']}")
    print(f"  total with TTE:    {s['total_with_tte']}")
    print(f"  tte_data:")
    for row in new["tte_data"]:
        print(f"    {row}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
