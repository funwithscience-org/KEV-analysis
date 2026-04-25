#!/usr/bin/env python3
"""
Build data/seven-year-manifest-events.json — the per-CVE event dataset
that backs the realManifestChart and the doc-canonical NP+DI table.

Source: data/_manifest-osv-cache.json (live OSV results for the manifest)

Per the prior AI's sense-check: the previous version of this dataset
used CWE-derived NP flags (commons-text events were tagged is_np=True
because CWE-94 is in PARSING_CWES, even though commons-text the
*package* is role=OTHER). That was wrong. This version derives is_np
from the *package role* in the manifest cache, with NP_OVERRIDES_TO_TRUE
for auth-boundary libraries the cache doesn't yet capture (cryptography,
bouncycastle if added later, etc.).

DI is still CWE-set based, with CWE-434 (file upload) excluded per the
periodicity doc's deliberate filter design.

Output: data/seven-year-manifest-events.json
    {
      methodology: { ... explicit rules ... },
      summary: { event counts, exploited counts },
      events: [ per-CVE records ],
    }

Usage:
    python3 scripts/build_seven_year_manifest_events.py
    python3 scripts/build_seven_year_manifest_events.py --check
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# DI CWE set. CWE-434 (file upload) deliberately excluded — see periodicity
# doc's deserialization callout (same volume rationale).
DI_CWES = {
    78, 77, 94, 95, 917, 1336, 74, 89, 90, 918, 611, 776, 444, 113, 22, 23,
    36, 98, 91, 116, 93, 96, 97, 1236,
    287, 289, 306, 345, 693, 863, 1321,
}

# Packages that must be NP for our analysis but the manifest cache
# doesn't tag with role="NP". Two reasons:
#
#   1. Auth-boundary libraries — process untrusted tokens/signatures/certs
#      and drive security decisions. See CLAUDE.md "NP Classification Rule".
#   2. Editorial additions to the seven-year backtest manifest that were
#      added with description-string role values (not "NP"/"OTHER"). The doc
#      treats these as NP for the 7-year analysis: log4j (JNDI parser),
#      xstream (XML deserializer that's a parser surface), activemq
#      (Jolokia HTTP-over-JMX, message protocol parser).
NP_OVERRIDES_TO_TRUE = {
    # match against bare package short name (last segment of Maven coord)
    # auth-boundary libraries
    "cryptography",
    "bcprov-jdk18on",
    "pyjwt",
    "jjwt",
    "jose",
    "jsonwebtoken",
    # editorial NP additions (doc treats these as NP)
    "log4j-core",
    "log4j-api",
    "xstream",
    "activemq-broker",
    "activemq-client",
    "activemq-core",
}


def short_pkg(full: str) -> str:
    return full.split(":", 1)[1] if ":" in full else full


def package_is_np(role: str, pkg: str) -> bool:
    """NP if manifest role is 'NP' OR package short name matches an override."""
    if role == "NP":
        return True
    return short_pkg(pkg) in NP_OVERRIDES_TO_TRUE


def build() -> dict:
    cache_path = REPO / "data" / "_manifest-osv-cache.json"
    if not cache_path.exists():
        raise FileNotFoundError(f"Run scripts/build_seven_year_npdi.py / "
                                f"OSV fetch first: {cache_path}")
    cache = json.load(open(cache_path))

    kev_path = REPO / "data" / "kev-snapshot-2026-04-23.json"
    kev_cves = {v["cveID"] for v in json.load(open(kev_path))["vulnerabilities"]}

    msf_path = REPO / "data" / "_metasploit-cves.json"
    msf_cves = set(json.load(open(msf_path)).get("cves", [])) if msf_path.exists() else set()

    edb_path = REPO / "data" / "_exploitdb-cves.json"
    edb_cves = set(json.load(open(edb_path)).get("cves", [])) if edb_path.exists() else set()

    # Index events by primary CVE; track which packages each CVE affects.
    by_cve: dict[str, dict] = {}
    for pkg_key, pkg_data in cache.items():
        eco, pkg = pkg_key.split("/", 1)
        role = pkg_data.get("role", "OTHER")
        for v in pkg_data.get("vulns", []):
            sev = v.get("database_specific", {}).get("severity", "").upper()
            if sev not in ("CRITICAL", "HIGH"):
                continue
            published = v.get("published", "")[:10]
            if published < "2018-01-01" or published > "2026-06-30":
                continue
            cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            primary = cves[0] if cves else v["id"]
            try:
                cve_year = int(primary.split("-")[1]) if primary.startswith("CVE-") else None
            except (IndexError, ValueError):
                cve_year = None
            if cve_year is not None and cve_year < 2018:
                continue
            cwe_strs = v.get("database_specific", {}).get("cwe_ids", []) or []
            cwe_nums = [int(c.replace("CWE-", "")) for c in cwe_strs
                        if re.match(r"CWE-\d+$", c)]
            entry = by_cve.setdefault(primary, {
                "cve": primary,
                "osv_id": v["id"],
                "packages": [],
                "package_roles": [],
                "cwes": cwe_strs,
                "cwe_nums": cwe_nums,
                "severity": sev,
                "published": published,
                "summary": v.get("summary", "")[:240],
            })
            entry["packages"].append(pkg)
            entry["package_roles"].append(role)

    # Per-CVE classification: an event is NP if ANY of its affected packages
    # is NP under our rule. DI if any of its CWEs is in DI set.
    events = []
    for cve, e in by_cve.items():
        e["packages"] = sorted(set(e["packages"]))
        e["package_roles"] = sorted(set(e["package_roles"]))
        any_np = any(package_is_np(role, pkg)
                     for pkg, role in zip(e["packages"], e["package_roles"]))
        # Re-pair with original list (may have multiple roles per package)
        any_np = any(package_is_np(role, pkg)
                     for role in e["package_roles"]
                     for pkg in e["packages"])
        # Simpler: any package whose short-name OR role hits NP wins
        any_np = (any(r == "NP" for r in e["package_roles"]) or
                  any(short_pkg(p) in NP_OVERRIDES_TO_TRUE for p in e["packages"]))
        any_di = any(c in DI_CWES for c in e["cwe_nums"])

        in_kev = cve in kev_cves
        in_msf = cve in msf_cves
        in_edb = cve in edb_cves

        events.append({
            **e,
            "is_np": any_np,
            "is_di": any_di,
            "in_kev": in_kev,
            "in_metasploit": in_msf,
            "in_exploitdb": in_edb,
            "exploited": in_kev or in_msf or in_edb,
        })

    # Sort: exploited NP+DI first, exploited non-NP+DI next, rest by date desc
    def sort_key(ev):
        g = (0 if (ev["exploited"] and ev["is_np"] and ev["is_di"]) else
             1 if ev["exploited"] else 2)
        d = -int((ev["published"] or "0000-00-00").replace("-", ""))
        return (g, d, ev["packages"][0] if ev["packages"] else "")
    events.sort(key=sort_key)

    cache_sha = hashlib.sha256(cache_path.read_bytes()).hexdigest()[:16]
    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Per-CVE event dataset for the 7-year manifest backtest. "
            "Built from data/_manifest-osv-cache.json with package-role-aware "
            "NP classification (a package is NP iff its role in the manifest "
            "is 'NP' OR its short name is in NP_OVERRIDES_TO_TRUE). DI is CWE-"
            "set based, excluding CWE-434 (file upload) per the doc's filter."
        ),
        "methodology": {
            "scope": "manifest from data/_manifest-osv-cache.json (54 packages)",
            "time_window": "2018-01-01 through 2026-06-30",
            "severity": "OSV CRITICAL or HIGH",
            "np_rule": (
                "Package-role-aware: role=='NP' OR short-name in "
                "NP_OVERRIDES_TO_TRUE. Auth-boundary libraries (cryptography, "
                "bouncycastle, JWT libs) are NP via override."
            ),
            "np_overrides": sorted(NP_OVERRIDES_TO_TRUE),
            "di_cwes": sorted(DI_CWES),
            "di_excludes": ["CWE-434 (file upload)", "CWE-502 (deserialization)"],
            "exploitation_sources": ["CISA KEV", "Metasploit", "ExploitDB"],
            "exploited_definition": "in_kev OR in_metasploit OR in_exploitdb",
        },
        "input_sources": {
            "manifest_cache": "data/_manifest-osv-cache.json",
            "manifest_cache_sha256_16": cache_sha,
            "kev_snapshot": "data/kev-snapshot-2026-04-23.json",
        },
        "summary": {
            "total_ch_events": len(events),
            "npdi_events": sum(1 for e in events if e["is_np"] and e["is_di"]),
            "exploited_total": sum(1 for e in events if e["exploited"]),
            "exploited_npdi": sum(1 for e in events if e["exploited"] and e["is_np"] and e["is_di"]),
            "exploited_np_not_di": sum(1 for e in events if e["exploited"] and e["is_np"] and not e["is_di"]),
            "exploited_not_np": sum(1 for e in events if e["exploited"] and not e["is_np"]),
            "in_kev_only": sum(1 for e in events if e["in_kev"]),
            "in_metasploit_only": sum(1 for e in events if e["in_metasploit"]),
            "in_exploitdb_only": sum(1 for e in events if e["in_exploitdb"]),
        },
        "events": events,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "seven-year-manifest-events.json"
    new = build()

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("events", "summary", "methodology", "description", "input_sources"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    s = new["summary"]
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  total C/H events:           {s['total_ch_events']}")
    print(f"  NP+DI events:               {s['npdi_events']}")
    print(f"  exploited (any source):     {s['exploited_total']}")
    print(f"    NP+DI ∩ exploited:        {s['exploited_npdi']}")
    print(f"    NP & not DI ∩ exploited:  {s['exploited_np_not_di']}")
    print(f"    not NP ∩ exploited:       {s['exploited_not_np']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
