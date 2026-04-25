#!/usr/bin/env python3
"""
Per-CWE exploitation backtest. For each CWE in the DI set (plus non-DI
controls), query NVD for all CVEs, filter to C/H 2022+, cross-reference
with KEV/MSF/EDB, compute exploitation rate.

Compares against the CWE-434 baseline (~4.1%) we computed earlier.
Hypothesis: included DI CWEs have higher exploitation rates than
CWE-434 (justifying their inclusion); CWE-434 is at the noise floor
(justifying its exclusion).

Cached: data/_nvd-cwe-cache/CWE-NNN.json per CWE.

Usage:
    python3 scripts/backtest_di_cwes.py             # fetch + analyze
    python3 scripts/backtest_di_cwes.py --skip-fetch  # use cache
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# Cache lives outside the repo: 425MB of raw NVD pulls, gitignored from
# data/_nvd-cwe-cache/ to keep repo size down. Override with NVD_CACHE_DIR
# env var if needed.
import os
CACHE_DIR = Path(os.environ.get("NVD_CACHE_DIR", "/tmp/nvd-cache"))
CACHE_DIR.mkdir(exist_ok=True, parents=True)

# DI CWEs (per current build_seven_year_npdi.py — CWE-434 already removed)
DI_CWES = [
    78,   # OS Command Injection
    77,   # Command Injection
    94,   # Code Injection
    95,   # Eval Injection
    917,  # EL Injection
    1336, # Template Injection
    74,   # Generic Injection
    89,   # SQL Injection
    90,   # LDAP Injection
    918,  # SSRF
    611,  # XXE
    776,  # XML Entity Expansion
    444,  # HTTP Request Smuggling
    113,  # CRLF / HTTP Response Splitting
    22,   # Path Traversal
    23,   # Relative Path Traversal
    36,   # Absolute Path Traversal
    98,   # PHP File Inclusion
    91,   # XML Injection
    116,  # Improper Output Encoding
    93,   # CRLF Injection
    96,   # Static Code Injection
    97,   # SSI Injection
    1236, # CSV Injection
    287,  # Improper Authentication (widened)
    289,  # Auth bypass via alternate name (widened)
    306,  # Missing auth for critical function (widened)
    345,  # Insufficient verification (widened)
    693,  # Protection mechanism failure (widened)
    863,  # Incorrect authorization (widened)
    1321, # Prototype pollution (widened)
]

# Controls (non-DI, for baseline comparison)
CONTROL_CWES = [
    434,  # File upload — already known 4.1% (will reproduce)
    79,   # XSS — should be low (non-DI, often low-impact)
    200,  # Information disclosure
    787,  # Out-of-bounds write (memory corruption)
    502,  # Deserialization (deliberately excluded from DI)
    269,  # Privilege management (Ghostcat misclassification case)
    20,   # Improper Input Validation (generic)
]


def fetch_cwe(cwe_num: int, throttle: float = 6.0) -> dict:
    """Fetch all NVD CVEs for a single CWE, paginated. Returns dict with
    'total', 'vulnerabilities'. Cached to disk; uses cache on subsequent runs."""
    cache_path = CACHE_DIR / f"CWE-{cwe_num}.json"
    if cache_path.exists():
        return json.load(open(cache_path))

    print(f"  Fetching CWE-{cwe_num}...", flush=True)
    start = 0
    all_cves = []
    total = None
    while True:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId=CWE-{cwe_num}&resultsPerPage=2000&startIndex={start}"
        req = urllib.request.Request(url, headers={"User-Agent": "KEV-Analysis/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.loads(r.read())
        except Exception as e:
            print(f"    ERROR at start={start}: {e}; sleeping 30s")
            time.sleep(30)
            continue
        if total is None:
            total = d.get("totalResults", 0)
            print(f"    total: {total}")
        vulns = d.get("vulnerabilities", [])
        all_cves.extend(vulns)
        if len(all_cves) >= total or not vulns:
            break
        start += len(vulns)
        time.sleep(throttle)

    out = {"cwe": cwe_num, "total": total, "vulnerabilities": all_cves}
    with open(cache_path, "w") as f:
        json.dump(out, f)
    print(f"    cached {len(all_cves)} entries")
    return out


def severity_of(cve_meta: dict) -> str | None:
    metrics = cve_meta.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if k in metrics and metrics[k]:
            return metrics[k][0].get("cvssData", {}).get("baseSeverity")
    return None


def published_year(cve_meta: dict) -> int | None:
    p = cve_meta.get("published", "")
    if p[:4].isdigit():
        return int(p[:4])
    return None


def analyze_cwe(cwe_num: int, raw: dict, kev_cves: set, msf: set, edb: set) -> dict:
    """For one CWE, compute C/H 2022+ count + exploitation breakdown."""
    events = []
    for entry in raw["vulnerabilities"]:
        c = entry["cve"]
        if severity_of(c) not in ("CRITICAL", "HIGH"):
            continue
        yr = published_year(c)
        if yr is None or yr < 2022:
            continue
        cve_id = c["id"]
        in_kev = cve_id in kev_cves
        in_msf = cve_id in msf
        in_edb = cve_id in edb
        events.append({
            "cve": cve_id, "year": yr,
            "in_kev": in_kev, "in_msf": in_msf, "in_edb": in_edb,
            "exploited": in_kev or in_msf or in_edb,
        })
    total = len(events)
    if total == 0:
        return {"cwe": cwe_num, "total_ch_2022plus": 0, "exploited": 0, "rate_pct": None}
    exploited = sum(1 for e in events if e["exploited"])
    in_kev = sum(1 for e in events if e["in_kev"])
    in_msf = sum(1 for e in events if e["in_msf"])
    in_edb = sum(1 for e in events if e["in_edb"])
    return {
        "cwe": cwe_num,
        "total_ch_2022plus": total,
        "exploited": exploited,
        "rate_pct": round(exploited / total * 100, 2),
        "in_kev": in_kev,
        "in_metasploit": in_msf,
        "in_exploitdb": in_edb,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-fetch", action="store_true",
                    help="Use cached files only; skip NVD requests for missing CWEs")
    args = ap.parse_args()

    with open(REPO / "data" / "kev-snapshot-2026-04-23.json") as f:
        kev_cves = {v["cveID"] for v in json.load(f)["vulnerabilities"]}
    msf = set(json.load(open(REPO / "data" / "_metasploit-cves.json"))["cves"])
    edb = set(json.load(open(REPO / "data" / "_exploitdb-cves.json"))["cves"])

    di_results = []
    print("=== Fetching DI CWEs ===")
    for cwe in DI_CWES:
        cache_path = CACHE_DIR / f"CWE-{cwe}.json"
        if args.skip_fetch and not cache_path.exists():
            print(f"  CWE-{cwe} not cached, skipping (--skip-fetch)")
            continue
        raw = fetch_cwe(cwe)
        di_results.append(analyze_cwe(cwe, raw, kev_cves, msf, edb))

    ctrl_results = []
    print("\n=== Fetching control CWEs ===")
    for cwe in CONTROL_CWES:
        cache_path = CACHE_DIR / f"CWE-{cwe}.json"
        if args.skip_fetch and not cache_path.exists():
            print(f"  CWE-{cwe} not cached, skipping")
            continue
        raw = fetch_cwe(cwe)
        ctrl_results.append(analyze_cwe(cwe, raw, kev_cves, msf, edb))

    out = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "scope": "C/H severity, published 2022+, exploitation = KEV ∪ MSF ∪ EDB",
        "di_cwes": sorted(di_results, key=lambda x: -(x["rate_pct"] or 0)),
        "control_cwes": sorted(ctrl_results, key=lambda x: -(x["rate_pct"] or 0)),
    }
    out_path = REPO / "data" / "di-cwe-backtest.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved {out_path.relative_to(REPO)}")

    print()
    print("=== DI CWEs (sorted by exploitation rate desc) ===")
    print(f"{'CWE':6s}  {'Total':5s}  {'Expl':4s}  {'Rate':6s}  {'KEV':4s} {'MSF':4s} {'EDB':4s}")
    for r in out["di_cwes"]:
        rate = f"{r['rate_pct']}%" if r['rate_pct'] is not None else "n/a"
        print(f"  CWE-{r['cwe']:<5d} {r['total_ch_2022plus']:5d}  {r['exploited']:4d}  {rate:6s}  "
              f"{r.get('in_kev','-'):>4} {r.get('in_metasploit','-'):>4} {r.get('in_exploitdb','-'):>4}")

    print()
    print("=== Control CWEs (non-DI, for baseline) ===")
    for r in out["control_cwes"]:
        rate = f"{r['rate_pct']}%" if r['rate_pct'] is not None else "n/a"
        print(f"  CWE-{r['cwe']:<5d} {r['total_ch_2022plus']:5d}  {r['exploited']:4d}  {rate:6s}  "
              f"{r.get('in_kev','-'):>4} {r.get('in_metasploit','-'):>4} {r.get('in_exploitdb','-'):>4}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
