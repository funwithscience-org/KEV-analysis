#!/usr/bin/env python3
"""Fetch lifetime RHSA advisory counts per RHEL major version from Red Hat's
Security Data API.

Endpoint: https://access.redhat.com/hydra/rest/securitydata/csaf.json

Each RHSA is a security advisory bundling fixes for one or more CVEs across
one or more affected packages. The `released_packages` field contains
package NVRs with `.el6/.el7/.el8/.el9` substrings indicating which RHEL
major version they're built for. We classify each advisory by which major
versions appear in its package list (an advisory can affect multiple).

Output: data/rhel-lifetime-advisories.json
  {
    "schema_version": 1,
    "generated": "YYYY-MM-DD",
    "source": "Red Hat Security Data API csaf.json",
    "by_year_by_version": {
      "2014": {"6": N, "7": M, "8": 0, "9": 0},
      ...
    },
    "lifetime_totals": {
      "6": <int>,
      "7": <int>,
      "8": <int>,
      "9": <int>
    },
    "first_n_years": {
      "6": [...per year...],
      "7": [...],
      ...
    },
    "advisories": [{"rhsa": "RHSA-2024:0208", "year": 2024, "severity": "low",
                    "versions": [8], "cves": [...]}]
  }

Run:
  python3 scripts/fetch_rhel_lifetime_advisories.py [--start 2010] [--end 2026] [--refresh]
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "data" / "_rhel-lifetime-cache"
CACHE.mkdir(parents=True, exist_ok=True)
OUT = REPO / "data" / "rhel-lifetime-advisories.json"

API = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"
EL_RE = re.compile(r"\.el(\d+)[._-]")  # matches .el6., .el7_2., .el8_6., .el9., etc.

UA = "KEV-analysis/research (russelst@melrosecastle.com)"


def fetch_year(year: int, refresh: bool = False) -> list[dict]:
    """Fetch all advisories for one year, paginated. Cache per-year JSON."""
    cache_path = CACHE / f"csaf-{year}.json"
    if cache_path.exists() and not refresh:
        return json.load(cache_path.open())

    advs: list[dict] = []
    page = 1
    per_page = 1000
    while True:
        url = (f"{API}?after={year}-01-01&before={year}-12-31"
               f"&per_page={per_page}&page={page}")
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                batch = json.loads(resp.read())
        except Exception as e:
            print(f"  ERR {year} page {page}: {e}", file=sys.stderr)
            time.sleep(5)
            continue
        if not batch:
            break
        advs.extend(batch)
        print(f"  {year} page {page}: +{len(batch)} (total {len(advs)})", file=sys.stderr)
        if len(batch) < per_page:
            break
        page += 1
        time.sleep(0.5)  # be polite

    cache_path.write_text(json.dumps(advs))
    return advs


def classify_advisory(adv: dict) -> set[int]:
    """Return the set of RHEL major versions this advisory affects."""
    pkgs = adv.get("released_packages") or []
    versions: set[int] = set()
    for p in pkgs:
        m = EL_RE.search(p)
        if m:
            v = int(m.group(1))
            if v in (6, 7, 8, 9, 10):
                versions.add(v)
    return versions


def main() -> int:
    start = 2010
    end = date.today().year
    refresh = "--refresh" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--start" in sys.argv:
        i = sys.argv.index("--start")
        start = int(sys.argv[i + 1])
    if "--end" in sys.argv:
        i = sys.argv.index("--end")
        end = int(sys.argv[i + 1])

    by_year_by_version: dict[str, dict[str, int]] = {}
    advisories_summary: list[dict] = []

    print(f"Fetching RHSA advisories {start}..{end}", file=sys.stderr)
    for year in range(start, end + 1):
        print(f"[{year}]", file=sys.stderr)
        advs = fetch_year(year, refresh=refresh)
        year_counts = {"6": 0, "7": 0, "8": 0, "9": 0, "10": 0}
        for adv in advs:
            versions = classify_advisory(adv)
            for v in versions:
                year_counts[str(v)] = year_counts.get(str(v), 0) + 1
            advisories_summary.append({
                "rhsa": adv.get("RHSA"),
                "year": year,
                "released_on": adv.get("released_on"),
                "severity": adv.get("severity"),
                "versions": sorted(versions),
                "cves": adv.get("CVEs", []),
            })
        by_year_by_version[str(year)] = year_counts
        print(f"  -> {year_counts}", file=sys.stderr)

    # Lifetime totals (sum across all years)
    lifetime = {"6": 0, "7": 0, "8": 0, "9": 0, "10": 0}
    for y, counts in by_year_by_version.items():
        for v, n in counts.items():
            lifetime[v] = lifetime.get(v, 0) + n

    # First-N-years per major version (for fair like-for-like comparison)
    ga_year = {"6": 2010, "7": 2014, "8": 2019, "9": 2022, "10": 2025}
    first_n_years: dict[str, list[int]] = {}
    for v, ga in ga_year.items():
        series = []
        for offset in range(0, end - ga + 1):
            y = str(ga + offset)
            series.append(by_year_by_version.get(y, {}).get(v, 0))
        first_n_years[v] = series

    out = {
        "schema_version": 1,
        "generated": date.today().isoformat(),
        "source": "Red Hat Security Data API csaf.json",
        "window": [start, end],
        "ga_year": ga_year,
        "by_year_by_version": by_year_by_version,
        "lifetime_totals": lifetime,
        "first_n_years_per_version": first_n_years,
        "advisories": advisories_summary,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {OUT}", file=sys.stderr)
    print(f"Lifetime totals: {lifetime}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
