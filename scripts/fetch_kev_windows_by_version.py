#!/usr/bin/env python3
"""For each Microsoft KEV entry, look up which Windows Server major versions
are affected (per MSRC), then aggregate to compute per-version KEV-rate.

This is the empirical test for the "Server 2022's mitigations make CVEs
harder to weaponize" claim on the evergreen page. If mitigations work in
practice, we'd expect:
  KEV-rate(newer Server) < KEV-rate(older Server)
where KEV-rate = (KEV-listed CVEs affecting this version) / (total CVEs
ever affecting this version, from windows-server-lifetime.json).

If the rates are roughly equal, it means among CVEs that hit all versions,
exploitation success doesn't meaningfully change with version — the
mitigation case is theoretical, not empirical.

Sources:
  - data/kev-snapshot-{latest}.json (CISA KEV catalog)
  - MSRC affectedProduct API (per-CVE → affected product list)
  - data/windows-server-lifetime.json (total CVE counts per version,
    used as denominator for the rate calculation)

Output: data/windows-kev-by-version.json

Run:
  python3 scripts/fetch_kev_windows_by_version.py [--refresh]
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "data" / "_msrc-lifetime-cache" / "per-cve"
CACHE.mkdir(parents=True, exist_ok=True)
OUT = REPO / "data" / "windows-kev-by-version.json"

API = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct"
UA = "KEV-analysis/research (russelst@melrosecastle.com)"

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
    # Lumped into a single SAC bucket; CVE-2020-0796 SMBGhost lives only here.
    ("SAC",    re.compile(r"\bWindows Server, version (?:1709|1803|1809|1903|1909|2004|20H2)\b", re.I)),
]


def classify(product_name: str) -> str | None:
    for k, p in VERSION_PATTERNS:
        if p.search(product_name or ""):
            return k
    return None


def find_kev_snapshot() -> Path:
    snaps = sorted((REPO / "data").glob("kev-snapshot-*.json"))
    if not snaps:
        print("ERROR: no KEV snapshot found in data/", file=sys.stderr)
        sys.exit(1)
    return snaps[-1]


def fetch_msrc_for_cve(cve: str, refresh: bool = False) -> list[dict] | None:
    cache_path = CACHE / f"{cve}.json"
    if cache_path.exists() and not refresh:
        try:
            return json.load(cache_path.open())
        except Exception:
            pass

    filt = urllib.parse.quote(f"cveNumber eq '{cve}'")
    url = f"{API}?$filter={filt}&$top=200"
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            cache_path.write_text("[]")
            return []
        print(f"  {cve}: HTTP {e.code}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  {cve}: {e}", file=sys.stderr)
        return None

    products = data.get("value", [])
    cache_path.write_text(json.dumps(products))
    time.sleep(0.3)
    return products


def main() -> int:
    refresh = "--refresh" in sys.argv

    kev_path = find_kev_snapshot()
    print(f"Using KEV snapshot: {kev_path.name}", file=sys.stderr)
    kev = json.load(kev_path.open())
    vulns = kev.get("vulnerabilities", [])

    # Filter to Microsoft entries (broader than just Windows Server,
    # since Office/SharePoint/Defender aren't Server CVEs)
    microsoft_kev = [v for v in vulns if (v.get("vendorProject") or "").lower() == "microsoft"]
    print(f"Total KEV entries: {len(vulns)}; Microsoft-vendor: {len(microsoft_kev)}", file=sys.stderr)

    # For each MS KEV CVE, look up affected Windows Server versions
    cve_to_versions: dict[str, set[str]] = {}
    cve_to_kev_meta: dict[str, dict] = {}
    no_msrc_match: list[str] = []
    not_a_server_cve: list[str] = []

    for i, v in enumerate(microsoft_kev):
        cve = v.get("cveID")
        if not cve:
            continue
        cve_to_kev_meta[cve] = {
            "cve": cve,
            "product": v.get("product"),
            "dateAdded": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse"),
            "shortDescription": (v.get("shortDescription") or "")[:200],
        }
        products = fetch_msrc_for_cve(cve, refresh=refresh)
        if products is None:
            continue
        if not products:
            no_msrc_match.append(cve)
            continue
        versions: set[str] = set()
        for p in products:
            pname = p.get("product") or p.get("baseProductName") or ""
            cls = classify(pname)
            if cls:
                versions.add(cls)
        if versions:
            cve_to_versions[cve] = versions
        else:
            not_a_server_cve.append(cve)
        if (i + 1) % 25 == 0:
            print(f"  [{i+1}/{len(microsoft_kev)}] {cve}: versions={sorted(versions)}", file=sys.stderr)

    # Aggregate: KEV CVEs per Windows Server version
    by_version: dict[str, list[str]] = defaultdict(list)
    for cve, versions in cve_to_versions.items():
        for v in versions:
            by_version[v].append(cve)

    # Compute KEV rate using lifetime totals as denominator
    lifetime_path = REPO / "data" / "windows-server-lifetime.json"
    lifetime = json.load(lifetime_path.open())["lifetime_totals"]

    rates = {}
    order = ["2008", "2008R2", "2012", "2012R2", "2016", "SAC", "2019", "2022", "2025"]
    for v in order:
        kev_count = len(by_version.get(v, []))
        total = lifetime.get(v, 0)
        rate = kev_count / total if total else 0
        rates[v] = {
            "kev_cves": kev_count,
            "lifetime_cves": total,
            "kev_rate_pct": round(100 * rate, 3),
        }

    out = {
        "schema_version": 1,
        "generated": date.today().isoformat(),
        "kev_snapshot": kev_path.name,
        "source_msrc": "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct",
        "_doc": "Per-Windows-Server-version KEV count + KEV-rate (KEV-listed CVEs / lifetime CVEs affecting that version). Tests whether mitigations measurably reduce real-world exploitation across versions.",
        "rates": rates,
        "by_version_cves": {v: sorted(cves) for v, cves in by_version.items()},
        "diagnostic": {
            "ms_kev_total": len(microsoft_kev),
            "ms_kev_with_server_match": len(cve_to_versions),
            "ms_kev_without_msrc_record": len(no_msrc_match),
            "ms_kev_not_server": len(not_a_server_cve),
            "no_msrc_match_examples": no_msrc_match[:10],
            "not_server_examples": not_a_server_cve[:10],
        },
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {OUT}", file=sys.stderr)
    print(f"\n=== KEV rate per Windows Server version ===", file=sys.stderr)
    for v in order:
        r = rates[v]
        print(f"  Server {v:6}: {r['kev_cves']:>3} KEV / {r['lifetime_cves']:>5} lifetime = {r['kev_rate_pct']}%", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
