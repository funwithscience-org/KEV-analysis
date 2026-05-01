#!/usr/bin/env python3
"""
Fetch and cache CVE publication dates for every KEV entry from the
2021+ window. Required by scripts/compute_tte.py.

Source: KEV snapshot (data/kev-snapshot-2026-05-01.json)
Lookup: OSV API per-CVE GET, with disk cache to avoid re-fetching.

Output: data/_kev-publication-dates.json
    {
      "CVE-2021-12345": {"published": "2021-XX-XX", "modified": "..."},
      ...
    }

Run once after a fresh KEV snapshot; cached entries are skipped on
subsequent runs.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE_PATH = REPO / "data" / "_kev-publication-dates.json"
SNAPSHOT_PATH = REPO / "data" / "kev-snapshot-2026-05-01.json"


def fetch_osv_published(cve: str, timeout: int = 15) -> str | None:
    url = f"https://api.osv.dev/v1/vulns/{cve}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.loads(r.read())
        return d.get("published")
    except Exception:
        return None


def main() -> int:
    snap = json.load(open(SNAPSHOT_PATH))
    cache: dict[str, dict] = {}
    if CACHE_PATH.exists():
        cache = json.load(open(CACHE_PATH))

    cves = []
    for v in snap["vulnerabilities"]:
        cve = v.get("cveID")
        if not cve:
            continue
        try:
            year = int(cve.split("-")[1])
        except (IndexError, ValueError):
            continue
        if year < 2021:
            continue
        cves.append(cve)

    print(f"KEV CVEs in window (2021+): {len(cves)}")
    print(f"Already cached: {len(cache)}")
    todo = [c for c in cves if c not in cache]
    print(f"To fetch: {len(todo)}")

    fetched = 0
    errors = 0
    for i, cve in enumerate(todo):
        published = fetch_osv_published(cve)
        if published:
            cache[cve] = {"published": published[:10]}
            fetched += 1
        else:
            cache[cve] = {"published": None, "error": "not_found_or_failed"}
            errors += 1
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(todo)} fetched (errors so far: {errors})")
            # Save mid-flight in case of interruption
            with open(CACHE_PATH, "w") as f:
                json.dump(cache, f, indent=2, sort_keys=True)
        time.sleep(0.05)

    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2, sort_keys=True)

    have_date = sum(1 for c, d in cache.items() if d.get("published"))
    print(f"\nWrote {CACHE_PATH.relative_to(REPO)}")
    print(f"  Total cached: {len(cache)}")
    print(f"  With published date: {have_date}")
    print(f"  Without (not found): {len(cache) - have_date}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
