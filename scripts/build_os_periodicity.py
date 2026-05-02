#!/usr/bin/env python3
"""
OS-layer periodicity backtest — produces cached-data/periodicity/os_periodicity_data.json.

Backs the dashboard's "OS Container Privesc Accumulation" chart and the
periodicity page's OS-layer chaining analysis. Queries NVD by keyword
(date filters return 404 on the public endpoint, so we filter client-side)
for ~20 OS-container components grouped into network parsers (curl, openssl,
nghttp2, libxml2, expat, krb5, python39, openjdk) and other OS surface
(glibc, systemd, sqlite, libarchive, zlib, xz, glib, pcre2, libyaml, rpm,
libgcrypt). Classifies each CVE by CWE family (NP, DI, MC) and attack
vector, then computes monthly counts + periodicity gaps.

Window: 2025-04-21 → 2026-04-21 (constants at top of file).

Run order in the daily refresh: this is NOT in the daily path. The OS
backtest is a slower component-by-component NVD walk; we re-run it on
demand when adding/removing OS components from the manifest, not nightly.
For nightly KEV+OS counts, see data/kev-classifier.py which classifies
the live KEV catalog by stack layer.

Usage:
    python3 scripts/build_os_periodicity.py
    # writes cached-data/periodicity/os_periodicity_data.json
"""

import json, urllib.request, time, sys
from datetime import datetime
from collections import defaultdict

START_DATE = "2025-04-21"
END_DATE = "2026-04-21"

# Direct injection CWEs
DI_CWES = {
    'CWE-78','CWE-77','CWE-22','CWE-23','CWE-36','CWE-94','CWE-95',
    'CWE-89','CWE-918','CWE-917','CWE-1336','CWE-116','CWE-74','CWE-75',
    'CWE-113','CWE-93','CWE-611','CWE-91','CWE-90','CWE-79',
}

MC_CWES = {
    'CWE-119','CWE-120','CWE-121','CWE-122','CWE-125','CWE-787',
    'CWE-416','CWE-415','CWE-190','CWE-191','CWE-476','CWE-401',
    'CWE-131','CWE-134','CWE-369','CWE-770','CWE-400','CWE-772','CWE-674',
}

# Components to query: (name, nvd_keyword, category, remote_reachable)
COMPONENTS = [
    # NP = network parser
    ("curl",        "curl haxx",    "NP", True,  "HTTP client library"),
    ("openssl",     "openssl",      "NP", True,  "TLS/SSL library"),
    ("nghttp2",     "nghttp2",      "NP", True,  "HTTP/2 parser"),
    ("libxml2",     "libxml2",      "NP", True,  "XML parser"),
    ("expat",       "expat",        "NP", True,  "XML SAX parser"),
    ("krb5",        "kerberos mit", "NP", True,  "Kerberos auth"),
    ("python39",    "cpython",      "NP", True,  "Python interpreter"),
    ("openjdk",     "openjdk",      "NP", True,  "Java Runtime"),
    # Non-NP
    ("glibc",       "glibc gnu",    "OTHER", False, "C library"),
    ("systemd",     "systemd",      "OTHER", False, "Init system"),
    ("sqlite",      "sqlite",       "OTHER", False, "Embedded database"),
    ("libarchive",  "libarchive",   "OTHER", False, "Archive handling"),
    ("zlib",        "zlib",         "OTHER", False, "Compression"),
    ("xz",          "xz tukaani",   "OTHER", False, "Compression"),
    ("glib",        "glib gnome",   "OTHER", False, "Utility library"),
    ("pcre2",       "pcre2",        "OTHER", False, "Regex library"),
    ("libyaml",     "libyaml",      "OTHER", False, "YAML parser"),
    ("rpm",         "rpm package",  "OTHER", False, "Package manager"),
    ("libgcrypt",   "libgcrypt",    "OTHER", False, "Crypto primitives"),
]


def query_nvd(keyword, start_index=0):
    """Query NVD keyword search, no date filter."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage=200&startIndex={start_index}"
    req = urllib.request.Request(url, headers={"User-Agent": "KEV-Analysis/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"    NVD error: {e}", file=sys.stderr)
        return {"vulnerabilities": [], "totalResults": 0}


def process_component(name, keyword, category, remote, role):
    """Fetch all CVEs for a component, filter to date range + C/H."""
    print(f"\n  [{name}] querying NVD keyword='{keyword}'...", flush=True)

    is_np = category == "NP"
    all_vulns = []

    # First page
    data = query_nvd(keyword)
    total = data.get("totalResults", 0)
    all_vulns.extend(data.get("vulnerabilities", []))
    print(f"    Total NVD results: {total}", flush=True)
    time.sleep(6.5)

    # Paginate if needed (only get first 400 — enough for recent)
    if total > 200:
        data2 = query_nvd(keyword, 200)
        all_vulns.extend(data2.get("vulnerabilities", []))
        time.sleep(6.5)

    # Filter to date range and C/H
    events = []
    for item in all_vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        pub = cve.get("published", "")[:10]

        if pub < START_DATE or pub > END_DATE:
            continue

        # Get CVSS
        score = 0
        severity = ""
        av = ""
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            for m in cve.get("metrics", {}).get(key, []):
                s = m.get("cvssData", {}).get("baseScore", 0)
                if s > score:
                    score = s
                    severity = m.get("cvssData", {}).get("baseSeverity", "")
                    av = m.get("cvssData", {}).get("attackVector", "")

        if score < 7.0:
            continue

        # Get description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # Verify relevance — check if component name appears in description or CPE
        desc_lower = desc.lower()
        name_lower = name.lower()
        kw_parts = keyword.lower().split()
        relevant = any(kw in desc_lower for kw in kw_parts if len(kw) > 3)

        # Also check CPE
        if not relevant:
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe = match.get("criteria", "").lower()
                        if any(kw in cpe for kw in kw_parts if len(kw) > 3):
                            relevant = True
                            break

        if not relevant:
            continue

        # Get CWEs
        cwes = set()
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val != "CWE-noinfo":
                    cwes.add(val)

        is_di = bool(cwes & DI_CWES)
        is_mc = bool(cwes & MC_CWES)

        events.append({
            "date": pub,
            "cve_id": cve_id,
            "component": name,
            "score": score,
            "severity": severity,
            "attack_vector": av,
            "cwes": list(cwes),
            "is_np": is_np,
            "is_remote": remote,
            "is_di": is_di,
            "is_mc": is_mc,
            "is_network_vector": av == "NETWORK",
            "summary": desc[:200],
            "role": role,
        })

    print(f"    → {len(events)} C/H in date range")
    for e in events:
        di_tag = " DI" if e["is_di"] else ""
        mc_tag = " MC" if e["is_mc"] else ""
        print(f"      {e['date']} {e['cve_id']} CVSS={e['score']} AV={e['attack_vector']}{di_tag}{mc_tag}")

    return events


def compute_gaps(dates):
    if len(dates) < 2:
        return {"count": len(dates), "gaps": [], "max_silence": None}
    gaps = []
    for i in range(1, len(dates)):
        d1 = datetime.strptime(dates[i-1], "%Y-%m-%d")
        d2 = datetime.strptime(dates[i], "%Y-%m-%d")
        gaps.append((d2 - d1).days)
    return {"count": len(dates), "gaps": gaps, "max_silence": max(gaps) if gaps else None}


def main():
    print("=" * 60)
    print("OS Container — 12-Month CVE Periodicity Backtest")
    print(f"Window: {START_DATE} to {END_DATE}")
    print("=" * 60)

    all_events = []
    for name, keyword, category, remote, role in COMPONENTS:
        events = process_component(name, keyword, category, remote, role)
        all_events.extend(events)

    all_events.sort(key=lambda e: e["date"])

    # Splits
    np_events = [e for e in all_events if e["is_np"]]
    np_di_events = [e for e in all_events if e["is_np"] and e["is_di"]]
    network_events = [e for e in all_events if e["is_network_vector"]]
    local_events = [e for e in all_events if e["attack_vector"] in ("LOCAL", "PHYSICAL")]
    mc_events = [e for e in all_events if e["is_mc"]]
    di_events = [e for e in all_events if e["is_di"]]
    # New filter: NP + network vector (remotely reachable NP bugs, regardless of CWE type)
    np_network_events = [e for e in all_events if e["is_np"] and e["is_network_vector"]]

    all_dates = sorted(set(e["date"] for e in all_events))
    np_di_dates = sorted(set(e["date"] for e in np_di_events))
    network_dates = sorted(set(e["date"] for e in network_events))
    local_dates = sorted(set(e["date"] for e in local_events))
    np_network_dates = sorted(set(e["date"] for e in np_network_events))

    # Monthly
    monthly = defaultdict(lambda: {"all":0,"np":0,"np_di":0,"mc":0,"network":0,"local":0})
    for e in all_events:
        m = e["date"][:7]
        monthly[m]["all"] += 1
        if e["is_np"]: monthly[m]["np"] += 1
        if e["is_np"] and e["is_di"]: monthly[m]["np_di"] += 1
        if e["is_mc"]: monthly[m]["mc"] += 1
        if e["is_network_vector"]: monthly[m]["network"] += 1
        if e["attack_vector"] in ("LOCAL","PHYSICAL"): monthly[m]["local"] += 1

    # By component
    comp_counts = defaultdict(int)
    for e in all_events:
        comp_counts[e["component"]] += 1

    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total C/H: {len(all_events)} on {len(all_dates)} dates")
    print(f"NP events: {len(np_events)}")
    print(f"NP+DI events: {len(np_di_events)} on {len(np_di_dates)} dates")
    print(f"Network vector: {len(network_events)} on {len(network_dates)} dates")
    print(f"Local vector: {len(local_events)} on {len(local_dates)} dates")
    print(f"Memory corruption: {len(mc_events)}")

    print(f"\nAttack vector split:")
    av_split = defaultdict(int)
    for e in all_events: av_split[e["attack_vector"]] += 1
    for av, c in sorted(av_split.items(), key=lambda x:-x[1]):
        print(f"  {av or 'UNKNOWN'}: {c} ({c*100//max(len(all_events),1)}%)")

    print(f"\nBy component:")
    for comp, c in sorted(comp_counts.items(), key=lambda x:-x[1]):
        cat = next((cat for n,_,cat,_,_ in COMPONENTS if n==comp), "?")
        print(f"  {comp} [{cat}]: {c}")

    print(f"\nPeriodicity:")
    print(f"  All C/H:   {compute_gaps(all_dates)}")
    print(f"  NP+DI:     {compute_gaps(np_di_dates)}")
    print(f"  Network:   {compute_gaps(network_dates)}")
    print(f"  NP+Network:{compute_gaps(np_network_dates)}")

    print(f"\nMonthly:")
    for m in sorted(monthly.keys()):
        v = monthly[m]
        print(f"  {m}: all={v['all']} np={v['np']} np_di={v['np_di']} mc={v['mc']} net={v['network']} local={v['local']}")

    # Save
    output = {
        "manifest_type": "os_container",
        "all_events": all_events,
        "np_di_events": np_di_events,
        "network_events": network_events,
        "all_dates": all_dates,
        "np_di_dates": np_di_dates,
        "network_dates": network_dates,
        "monthly": dict(monthly),
        "component_counts": dict(comp_counts),
        "attack_vector_split": dict(av_split),
    }
    out_path = "cached-data/periodicity/os_periodicity_data.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
