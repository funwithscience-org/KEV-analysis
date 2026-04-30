#!/usr/bin/env python3
"""Fetch Windows Server CVE counts per major version per year from MSRC's
CVRF API.

Endpoint: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-Mon}

Each monthly Patch Tuesday bulletin lists all CVEs disclosed that month,
with `Vulnerability[].ProductStatuses[].ProductID[]` mapping CVEs to product
IDs. The `ProductTree.FullProductName[]` array maps each product ID to a
human-readable name from which we parse the Windows Server major version.

Output: data/windows-server-lifetime.json
  {
    "schema_version": 1,
    "generated": "YYYY-MM-DD",
    "source": "MSRC CVRF API",
    "by_year_by_version": {
      "2017": {"2008R2": N, "2012": N, "2012R2": N, "2016": N, ...},
      ...
    },
    "lifetime_totals": { "2016": N, ... },
    "ga_year": { "2016": 2016, "2019": 2018, "2022": 2021, "2025": 2024 },
    "first_n_years_per_version": { "2016": [Y1, Y2, ...], ... }
  }

The CVRF API is unauthenticated and rate-tolerant. Per-month JSON is cached
under data/_msrc-lifetime-cache/ to make re-runs cheap.

Run:
  python3 scripts/fetch_windows_server_lifetime.py [--start 2016] [--end 2026] [--refresh]
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "data" / "_msrc-lifetime-cache"
CACHE.mkdir(parents=True, exist_ok=True)
OUT = REPO / "data" / "windows-server-lifetime.json"

API = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
UA = "KEV-analysis/research (russelst@melrosecastle.com)"
MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

# Windows Server major-version detection. Order matters: 2012 R2 must be
# checked before 2012, etc. Returns the version key or None.
VERSION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("2008R2", re.compile(r"\bWindows Server 2008 R2\b", re.I)),
    ("2008",   re.compile(r"\bWindows Server 2008\b(?! R2)", re.I)),
    ("2012R2", re.compile(r"\bWindows Server 2012 R2\b", re.I)),
    ("2012",   re.compile(r"\bWindows Server 2012\b(?! R2)", re.I)),
    ("2016",   re.compile(r"\bWindows Server 2016\b", re.I)),
    ("2019",   re.compile(r"\bWindows Server 2019\b", re.I)),
    ("2022",   re.compile(r"\bWindows Server 2022\b", re.I)),
    ("2025",   re.compile(r"\bWindows Server 2025\b", re.I)),
    # Semi-Annual Channel (Sep 2017 – Aug 2021, then discontinued).
    # Versions: 1709, 1803, 1809, 1903, 1909, 2004, 20H2. Lumped into a
    # single SAC bucket because they were a side-track of overlapping
    # short-lived releases sharing 2016/2019-era code; the LTSC chart
    # is the main story. CVE-2020-0796 SMBGhost (SMBv3 RCE) lives only
    # here — without this bucket it gets dropped entirely from the
    # per-version stats.
    ("SAC",    re.compile(r"\bWindows Server, version (?:1709|1803|1809|1903|1909|2004|20H2)\b", re.I)),
]

# GA years for first-N-years comparison. ESU (paid extended support) is
# a separate question — these are when the product first shipped.
GA_YEAR = {
    "2008R2": 2009,
    "2012":   2012,
    "2012R2": 2013,
    "2016":   2016,
    "2019":   2018,
    "2022":   2021,
    "2025":   2024,
    "SAC":    2017,  # 1709 was first SAC release
}


def fetch_month(year: int, month: int, refresh: bool = False) -> dict | None:
    bulletin_id = f"{year}-{MONTHS[month-1]}"
    cache_path = CACHE / f"{bulletin_id}.json"
    if cache_path.exists() and not refresh:
        try:
            return json.load(cache_path.open())
        except Exception:
            pass  # cache corrupt; refetch

    url = f"{API}/{bulletin_id}"
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  {bulletin_id}: 404 (no bulletin issued)", file=sys.stderr)
            cache_path.write_text("null")
            return None
        print(f"  {bulletin_id}: HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  {bulletin_id}: {e}", file=sys.stderr)
        return None

    cache_path.write_text(json.dumps(data))
    time.sleep(0.4)
    return data


def classify_version(product_name: str) -> str | None:
    """Return the Windows Server major-version key (e.g. '2016') or None."""
    for key, pat in VERSION_PATTERNS:
        if pat.search(product_name or ""):
            return key
    return None


def extract_versions_per_cve(bulletin: dict) -> dict[str, set[str]]:
    """For one CVRF document, return {cve: {versions...}}.

    A CVE is counted once per Windows Server major version it touches in this
    bulletin. The same CVE can appear in multiple bulletins over time, but we
    count it once-per-bulletin-per-version (so a re-issue in a later month
    counts again — Microsoft sometimes re-publishes when scope changes).
    """
    fpn = (bulletin.get("ProductTree") or {}).get("FullProductName") or []
    pid_to_version: dict[str, str] = {}
    for entry in fpn:
        pid = str(entry.get("ProductID") or "")
        ver = classify_version(entry.get("Value") or "")
        if ver:
            pid_to_version[pid] = ver

    out: dict[str, set[str]] = {}
    for v in bulletin.get("Vulnerability") or []:
        cve = v.get("CVE")
        if not cve:
            continue
        affected: set[str] = set()
        for ps in v.get("ProductStatuses") or []:
            for pid in ps.get("ProductID") or []:
                pid_str = str(pid)
                # Compound IDs like "11650-10049" mean App-on-OS — match either segment
                for segment in pid_str.split("-"):
                    if segment in pid_to_version:
                        affected.add(pid_to_version[segment])
        if affected:
            out.setdefault(cve, set()).update(affected)
    return out


def main() -> int:
    start = 2016
    end = date.today().year
    refresh = "--refresh" in sys.argv
    if "--start" in sys.argv:
        start = int(sys.argv[sys.argv.index("--start") + 1])
    if "--end" in sys.argv:
        end = int(sys.argv[sys.argv.index("--end") + 1])

    by_year_by_version: dict[str, dict[str, int]] = {}
    cve_year_version: dict[tuple[str, str, str], int] = defaultdict(int)

    print(f"Fetching MSRC CVRF bulletins {start}..{end}", file=sys.stderr)
    today_month = date.today().month
    for year in range(start, end + 1):
        max_month = today_month if year == date.today().year else 12
        year_versions: dict[str, set[str]] = defaultdict(set)
        for month in range(1, max_month + 1):
            bul = fetch_month(year, month, refresh=refresh)
            if not bul:
                continue
            cve_versions = extract_versions_per_cve(bul)
            for cve, versions in cve_versions.items():
                for v in versions:
                    year_versions[v].add(cve)
        year_counts = {ver: len(cves) for ver, cves in year_versions.items()}
        by_year_by_version[str(year)] = year_counts
        print(f"[{year}] {year_counts}", file=sys.stderr)

    # Lifetime totals (sum across years)
    lifetime: dict[str, int] = defaultdict(int)
    for y, counts in by_year_by_version.items():
        for v, n in counts.items():
            lifetime[v] += n

    # First-N-years per version (apples-to-apples)
    first_n_years: dict[str, list[int]] = {}
    for v, ga in GA_YEAR.items():
        if ga < start:
            # Data starts mid-life; first_n is from `start` not GA
            first_n_years[v] = []
            continue
        series = []
        for offset in range(0, end - ga + 1):
            y = str(ga + offset)
            series.append(by_year_by_version.get(y, {}).get(v, 0))
        first_n_years[v] = series

    out = {
        "schema_version": 1,
        "generated": date.today().isoformat(),
        "source": "MSRC CVRF API (https://api.msrc.microsoft.com/cvrf/v3.0)",
        "window": [start, end],
        "ga_year": GA_YEAR,
        "by_year_by_version": by_year_by_version,
        "lifetime_totals": dict(lifetime),
        "first_n_years_per_version": first_n_years,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {OUT}", file=sys.stderr)
    print(f"Lifetime totals: {dict(lifetime)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
