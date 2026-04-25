#!/usr/bin/env python3
"""
Extend the 12-month per-framework backtest (Spring/Node/Django/Netty) to a
7-year window by re-querying OSV for each manifest's full vuln history.

Question being answered: does the 12-month "perfect catch" hold over 7 years?
Or does the small N of the 12-month sample mask real catch-rate gaps that
appear in the longer view?

Outputs: data/_seven-year-frameworks-cache.json (raw OSV results, multi-fw)
         data/seven-year-per-framework.json     (per-framework rollup)

Usage:
    python3 scripts/extend_frameworks_to_seven_year.py        # fetch + analyze
    python3 scripts/extend_frameworks_to_seven_year.py --skip-fetch  # use cache
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE_DIR = Path("/sessions/bold-nice-euler/mnt/vulnerability analysis")

DI_CWES = {78, 77, 94, 95, 917, 1336, 74, 89, 90, 918, 611, 776, 444, 113, 22, 23,
           36, 98, 91, 116, 93, 96, 97, 1236,
           287, 289, 306, 345, 693, 863, 1321}

NP_OVERRIDES_TO_TRUE = {"cryptography", "bcprov-jdk18on", "pyjwt", "jjwt",
                        "jose", "jsonwebtoken", "log4j-core", "log4j-api",
                        "xstream", "activemq-broker", "activemq-client",
                        "activemq-core"}


def load_node_manifest():
    src = (CACHE_DIR / "analysis-scripts/multi_framework_periodicity.py").read_text()
    m = re.search(r'NODE_MANIFEST\s*=\s*\[(.*?)\n\]', src, re.DOTALL)
    return re.findall(r'\{[^}]*"package":\s*"([^"]+)"[^}]*"category":\s*"([^"]+)"', m.group(1))


def load_django_manifest():
    src = (CACHE_DIR / "analysis-scripts/multi_framework_periodicity.py").read_text()
    m = re.search(r'DJANGO_MANIFEST\s*=\s*\[(.*?)\n\]', src, re.DOTALL)
    return re.findall(r'\{[^}]*"package":\s*"([^"]+)"[^}]*"category":\s*"([^"]+)"', m.group(1))


def load_netty_manifest():
    # Same set as scripts/fetch_netty_osv.py
    return [
        ("io.netty:netty-codec-http",  "NP"),
        ("io.netty:netty-codec-http2", "NP"),
        ("io.netty:netty-codec",       "NP"),
        ("io.netty:netty-handler",     "NP"),
        ("io.netty:netty-transport",   "OTHER"),
        ("io.netty:netty-buffer",      "OTHER"),
        ("io.netty:netty-common",      "OTHER"),
    ]


def load_spring_manifest():
    src = (CACHE_DIR / "analysis-scripts/spring_manifest_analysis.py").read_text()
    m = re.search(r'MANIFEST = \[(.*?)\n\]', src, re.DOTALL)
    raw = re.findall(r'\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)', m.group(1))
    return [(pkg, role) for _, pkg, role, _ in raw]


def query_osv(eco, pkg):
    body = json.dumps({"package": {"name": pkg, "ecosystem": eco}}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("vulns", [])


def fetch_framework(name, eco, packages):
    """packages = list of (pkg_name, role)"""
    out = {"framework": name, "manifest_size": len(packages),
           "manifest": [{"package": p, "role": r} for p, r in packages],
           "raw_vulns": {}, "fetched_at": dt.datetime.utcnow().isoformat() + "Z"}
    for pkg, role in packages:
        print(f"    {pkg} ...", end=" ", flush=True)
        try:
            vulns = query_osv(eco, pkg)
            out["raw_vulns"][pkg] = vulns
            print(f"{len(vulns)}")
        except Exception as e:
            print(f"ERROR: {e}")
            out["raw_vulns"][pkg] = []
        time.sleep(0.15)
    return out


def short(p): return p.split(":", 1)[1] if ":" in p else p


def is_np(pkg, role):
    if role == "NP": return True
    return short(pkg) in NP_OVERRIDES_TO_TRUE


def analyze(framework_data, kev_cves, msf_cves, edb_cves):
    """Compute per-window catch rates for one framework."""
    name = framework_data["framework"]
    np_packages = {m["package"]: m["role"] for m in framework_data["manifest"]}

    by_cve = {}
    for pkg, vulns in framework_data["raw_vulns"].items():
        role = np_packages.get(pkg, "OTHER")
        pkg_is_np = is_np(pkg, role)
        for v in vulns:
            sev = v.get("database_specific", {}).get("severity", "").upper()
            if sev not in ("CRITICAL", "HIGH"): continue
            published = v.get("published", "")[:10]
            if not published or published < "2018-01-01" or published > "2026-06-30": continue
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            primary = cves[0] if cves else v["id"]
            try:
                cve_year = int(primary.split("-")[1]) if primary.startswith("CVE-") else None
            except (IndexError, ValueError):
                cve_year = None
            if cve_year is not None and cve_year < 2018: continue
            cwe_strs = v.get("database_specific", {}).get("cwe_ids", []) or []
            cwe_nums = [int(c.replace("CWE-","")) for c in cwe_strs if re.match(r"CWE-\d+$", c)]
            cwe_di = any(c in DI_CWES for c in cwe_nums)
            entry = by_cve.setdefault(primary, {
                "cve": primary, "year": cve_year, "published": published,
                "packages": [], "package_roles": [], "cwes": cwe_nums,
                "is_np": False, "is_di": cwe_di, "exploited": False,
            })
            entry["packages"].append(pkg)
            entry["package_roles"].append(role)
            if pkg_is_np: entry["is_np"] = True
            if primary in kev_cves or primary in msf_cves or primary in edb_cves:
                entry["exploited"] = True

    events = list(by_cve.values())
    for e in events:
        e["is_npdi"] = e["is_np"] and e["is_di"]

    # Per-window rollup
    def window(year):
        if year is None: return "?"
        if year <= 2019: return "2018-2019"
        if year <= 2021: return "2020-2021"
        if year <= 2023: return "2022-2023"
        return "2024-2026"

    windows = {}
    for w in ("2018-2019","2020-2021","2022-2023","2024-2026"):
        ws = [e for e in events if window(e["year"]) == w]
        expl = [e for e in ws if e["exploited"]]
        caught = [e for e in expl if e["is_npdi"]]
        missed = [e for e in expl if not e["is_npdi"]]
        windows[w] = {
            "ch_total": len(ws),
            "npdi": sum(1 for e in ws if e["is_npdi"]),
            "exploited": len(expl),
            "caught": len(caught),
            "missed": len(missed),
            "missed_details": [{"cve": e["cve"], "package": e["packages"][0],
                                "cwes": e["cwes"], "is_np": e["is_np"], "is_di": e["is_di"]}
                               for e in missed],
        }

    # Whole 7-year totals
    expl_all = [e for e in events if e["exploited"]]
    caught_all = [e for e in expl_all if e["is_npdi"]]
    return {
        "framework": name,
        "total_ch_7yr": len(events),
        "npdi_7yr": sum(1 for e in events if e["is_npdi"]),
        "exploited_7yr": len(expl_all),
        "caught_7yr": len(caught_all),
        "missed_7yr": len(expl_all) - len(caught_all),
        "catch_rate_7yr_pct": round(len(caught_all)/len(expl_all)*100, 1) if expl_all else None,
        "by_window": windows,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-fetch", action="store_true",
                    help="Use cached data, don't re-fetch OSV")
    args = ap.parse_args()

    cache_path = REPO / "data" / "_seven-year-frameworks-cache.json"

    if args.skip_fetch and cache_path.exists():
        print(f"Loading cache: {cache_path.relative_to(REPO)}")
        cache = json.load(open(cache_path))
    else:
        print("Fetching 7-year OSV data for Spring/Node/Django/Netty...")
        cache = {}
        # Spring uses the existing manifest cache (already 7-year). Skip re-fetch.
        # Just synthesize a "framework" structure from it.
        with open(REPO / "data" / "_manifest-osv-cache.json") as f:
            mfst_cache = json.load(f)
        spring_pkgs = load_spring_manifest()
        spring_pkg_set = {p for p, _ in spring_pkgs}
        spring_data = {
            "framework": "spring", "manifest_size": len(spring_pkgs),
            "manifest": [{"package": p, "role": r} for p, r in spring_pkgs],
            "raw_vulns": {},
        }
        for k, v in mfst_cache.items():
            eco, pkg = k.split("/", 1)
            if pkg in spring_pkg_set:
                spring_data["raw_vulns"][pkg] = v.get("vulns", [])
        cache["spring"] = spring_data

        # Node, Django: need to fetch from OSV
        for name, pkgs, eco in [("nodejs", load_node_manifest(), "npm"),
                                ("django", load_django_manifest(), "PyPI"),
                                ("netty", load_netty_manifest(), "Maven")]:
            print(f"  {name} ({len(pkgs)} packages, eco={eco}):")
            cache[name] = fetch_framework(name, eco, pkgs)

        with open(cache_path, "w") as f:
            json.dump(cache, f, indent=2)
        print(f"\nWrote {cache_path.relative_to(REPO)}")

    # Now analyze
    with open(REPO / "data" / "kev-snapshot-2026-04-23.json") as f:
        kev_cves = {v["cveID"] for v in json.load(f)["vulnerabilities"]}
    msf_cves = set(json.load(open(REPO / "data" / "_metasploit-cves.json"))["cves"])
    edb_cves = set(json.load(open(REPO / "data" / "_exploitdb-cves.json"))["cves"])

    out = {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "7-year-window per-framework backtest. Tests whether the "
            "12-month 'perfect catch' claim holds when extended to 7 years. "
            "If small-N samples were over-promising, the 7-year view should "
            "show real catch-rate gaps."
        ),
        "frameworks": {},
    }
    for name in ("spring", "nodejs", "django", "netty"):
        if name not in cache: continue
        out["frameworks"][name] = analyze(cache[name], kev_cves, msf_cves, edb_cves)

    out_path = REPO / "data" / "seven-year-per-framework.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {out_path.relative_to(REPO)}")
    print()
    print("=== Per-framework 7-year totals ===")
    print(f"{'Framework':10s} {'C/H':5s} {'NP+DI':6s} {'Expl':5s} {'Caught':7s} {'Missed':7s} {'Rate':6s}")
    for name, r in out["frameworks"].items():
        rate = f"{r['catch_rate_7yr_pct']}%" if r['catch_rate_7yr_pct'] is not None else "n/a"
        print(f"  {name:8s} {r['total_ch_7yr']:5d} {r['npdi_7yr']:6d} {r['exploited_7yr']:5d} {r['caught_7yr']:7d} {r['missed_7yr']:7d} {rate:6s}")
    print()
    print("=== Per-window detail ===")
    for name, r in out["frameworks"].items():
        print(f"\n  {name}:")
        for w, ws in r["by_window"].items():
            rate = f"{ws['caught']}/{ws['exploited']}" if ws['exploited'] else "n/a"
            print(f"    {w}: {ws['ch_total']:3d} C/H, {ws['npdi']:2d} NP+DI, "
                  f"{ws['exploited']} expl, {ws['caught']} caught, {ws['missed']} missed ({rate})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
