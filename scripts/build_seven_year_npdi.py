#!/usr/bin/env python3
"""
Build the canonical seven-year NP+DI events dataset.

Sources:
  1. OSV CWE-classification cache for 24 popular network-parsing libraries
     (cached-data/osv/osv_cwe_results.json, the same source backing the OSV
     exploitation scratch page)
  2. CISA KEV catalog snapshot (data/kev-snapshot-2026-04-23.json) — for
     in-KEV outcome flag
  3. Spring Boot 60-package manifest (extracted from
     analysis-scripts/spring_manifest_analysis.py) — used to flag whether
     each event is in the manifest scope or in the broader popular-library
     scope
  4. Metasploit + ExploitDB caches (cached-data/epss/) — for cross-source
     exploitation outcome
  5. EPSS results (cached-data/epss/epss_results.json) — for events that
     overlap with the 12-month synthetic backtest

Output:
  data/seven-year-npdi-events.json — single file with per-event records and
  a summary block. Reproducible from the cached inputs.

Usage:
    python3 scripts/build_seven_year_npdi.py
    python3 scripts/build_seven_year_npdi.py --check    # exit 1 if regen would change
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = Path("/sessions/bold-nice-euler/mnt/vulnerability analysis/cached-data")

# Direct-injection CWE set used by the project's NP+DI filter.
# Source: kev_cwe_backtest.py (analysis-scripts/) plus auth-bypass widening
# from data/di-reclassification.json (April 2026).
DI_CWES = {
    # Original DI definition (network parser-style injection)
    78, 77, 94, 95, 917, 1336, 74, 89, 90, 918, 611, 776, 444, 113, 22, 23,
    36, 434, 98, 91, 116, 93, 96, 97, 1236,
    # Auth-bypass widening (April 2026)
    287, 289, 306, 345, 693, 863, 1321,
}


def load_manifest() -> set[tuple[str, str]]:
    """Pull the 60-package Spring Boot manifest from the analysis script."""
    src = (CACHE.parent / "analysis-scripts" / "spring_manifest_analysis.py").read_text()
    m = re.search(r'MANIFEST = \[(.*?)\n\]', src, re.DOTALL)
    if not m:
        raise RuntimeError("Could not extract MANIFEST from spring_manifest_analysis.py")
    pkgs = re.findall(r'\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)"\)', m.group(1))
    return {(eco, pkg) for eco, pkg, _, _ in pkgs}


def load_kev_cve_set() -> set[str]:
    """All CVE IDs in the local KEV snapshot."""
    with open(REPO / "data" / "kev-snapshot-2026-04-23.json") as f:
        kev = json.load(f)
    return {v["cveID"] for v in kev["vulnerabilities"]}


def load_metasploit_cves() -> set[str]:
    """Full Metasploit module CVE list, cached in data/_metasploit-cves.json
    (~3,100 CVEs from rapid7/metasploit-framework's modules_metadata_base.json).
    Falls back to the small 12-month cache if the full one isn't present."""
    p = REPO / "data" / "_metasploit-cves.json"
    if p.exists():
        return set(json.load(open(p)).get("cves", []))
    p = CACHE / "epss" / "metasploit_results.json"
    if p.exists():
        return set(json.load(open(p)).get("our_matches", []))
    return set()


def load_exploitdb_cves() -> set[str]:
    """Full ExploitDB CVE list, cached in data/_exploitdb-cves.json
    (~25,000 CVEs from gitlab.com/exploit-database/exploitdb files_exploits.csv).
    Falls back to the small 12-month cache if the full one isn't present."""
    p = REPO / "data" / "_exploitdb-cves.json"
    if p.exists():
        return set(json.load(open(p)).get("cves", []))
    p = CACHE / "epss" / "exploitdb_results.json"
    if p.exists():
        return set(json.load(open(p)).get("our_matches", []))
    return set()


def load_epss_lookup() -> dict[str, float]:
    """EPSS score per CVE for the 12-month dataset."""
    p = CACHE / "epss" / "epss_results.json"
    if not p.exists():
        return {}
    with open(p) as f:
        rows = json.load(f)
    out = {}
    for r in rows:
        cve = r.get("cve")
        if cve and r.get("epss") is not None:
            out[cve] = r["epss"]
    return out


def load_alias_cache() -> dict[str, dict]:
    """OSV alias lookups cached in data/_osv-alias-cache.json. The cache is
    committed to the repo for reproducibility — the dataset rebuild never
    queries OSV at test time."""
    p = REPO / "data" / "_osv-alias-cache.json"
    return json.load(open(p)) if p.exists() else {}


def extract_cve(osv_id: str, summary: str, alias_cache: dict) -> str | None:
    """Resolve an OSV event ID to its primary CVE alias.
    Priority:
      1. ID is itself a CVE → return as-is.
      2. Alias cache has a CVE alias → return the first one.
      3. Summary text embeds a CVE → regex extract.
    """
    if osv_id and osv_id.startswith("CVE-"):
        return osv_id
    cve_aliases = [a for a in alias_cache.get(osv_id, {}).get("aliases", [])
                   if a.startswith("CVE-")]
    if cve_aliases:
        return cve_aliases[0]
    if summary:
        m = re.search(r"\bCVE-\d{4}-\d{4,7}\b", summary)
        if m:
            return m.group(0)
    return None


def extract_published(osv_id: str, alias_cache: dict) -> str | None:
    """Pull published date (YYYY-MM-DD) from the alias cache."""
    p = alias_cache.get(osv_id, {}).get("published")
    return p[:10] if p else None


def build_events() -> list[dict]:
    """Pull NP+DI events from the OSV cache and enrich with outcome flags."""
    with open(CACHE / "osv" / "osv_cwe_results.json") as f:
        osv = json.load(f)

    manifest = load_manifest()
    kev_cves = load_kev_cve_set()
    msf_cves = load_metasploit_cves()
    edb_cves = load_exploitdb_cves()
    epss = load_epss_lookup()
    alias_cache = load_alias_cache()

    events = []
    for pkg_data in osv:
        eco = pkg_data["ecosystem"]
        pkg = pkg_data["package"]
        in_manifest = (eco, pkg) in manifest
        for ev in pkg_data.get("details", []):
            cwe = ev.get("cwe")
            is_di = isinstance(cwe, int) and cwe in DI_CWES
            is_np = ev.get("classification") == "parsing_surface"
            if not (is_np and is_di):
                continue
            osv_id = ev.get("id", "") or ""
            summary = ev.get("summary", "") or ""
            cve = extract_cve(osv_id, summary, alias_cache)
            published = extract_published(osv_id, alias_cache)
            in_kev_flag = bool(cve and cve in kev_cves)
            in_msf_flag = bool(cve and cve in msf_cves)
            in_edb_flag = bool(cve and cve in edb_cves)
            events.append({
                "osv_id": osv_id,
                "cve": cve,
                "published": published,
                "package": pkg,
                "ecosystem": eco,
                "in_manifest": in_manifest,
                "cwe": cwe,
                "summary": summary[:240],
                "is_np": True,
                "is_di": True,
                # Per-source flags
                "in_kev":      in_kev_flag,
                "in_metasploit": in_msf_flag,
                "in_exploitdb":  in_edb_flag,
                # Union: any exploitation evidence
                "exploited":   in_kev_flag or in_msf_flag or in_edb_flag,
                "epss": epss.get(cve) if cve else None,
            })
    return events


def build_summary(events: list[dict]) -> dict:
    by_pkg = Counter(e["package"] for e in events)
    by_eco = Counter(e["ecosystem"] for e in events)
    by_cwe = Counter(f"CWE-{e['cwe']}" for e in events)
    in_manifest = [e for e in events if e["in_manifest"]]
    in_kev = [e for e in events if e["in_kev"]]
    in_msf = [e for e in events if e["in_metasploit"]]
    in_edb = [e for e in events if e["in_exploitdb"]]
    exploited = [e for e in events if e["exploited"]]
    in_kev_manifest = [e for e in events if e["in_kev"] and e["in_manifest"]]
    return {
        "total_events": len(events),
        "in_manifest_count": len(in_manifest),
        # Per-source exploitation counts
        "in_kev_count": len(in_kev),
        "in_metasploit_count": len(in_msf),
        "in_exploitdb_count": len(in_edb),
        # Union -- this is the "exploited" denominator that should be used
        # for any high-vs-low analysis. KEV alone undercounts library
        # exploitation; the project explicitly pivoted to OSV+Metasploit
        # for library-scope exploitation evidence.
        "exploited_count": len(exploited),
        "in_kev_and_manifest_count": len(in_kev_manifest),
        "by_ecosystem": dict(by_eco),
        "by_package": dict(by_pkg.most_common()),
        "by_cwe": dict(by_cwe.most_common()),
        "with_cve_id": sum(1 for e in events if e["cve"]),
        "with_epss_score": sum(1 for e in events if e["epss"] is not None),
    }


def render_dataset() -> dict:
    events = build_events()
    summary = build_summary(events)

    # Hash the input cache so reproducibility is verifiable
    osv_path = CACHE / "osv" / "osv_cwe_results.json"
    osv_sha = hashlib.sha256(osv_path.read_bytes()).hexdigest()[:16]
    kev_path = REPO / "data" / "kev-snapshot-2026-04-23.json"
    kev_sha = hashlib.sha256(kev_path.read_bytes()).hexdigest()[:16]

    # Sort: exploited first (any source), then by published date desc.
    # 'exploited' is the union (KEV ∪ Metasploit ∪ ExploitDB) -- using KEV
    # alone undercounts library exploitation per the project's framing.
    def date_key(e):
        d = e["published"] or "0000-00-00"
        return -int(d.replace("-", ""))
    events.sort(key=lambda e: (not e["exploited"], date_key(e), e["package"], e["cwe"] or 0))

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Seven-year network-parser + direct-injection (NP+DI) events dataset. "
            "Built from the cached OSV CWE-classification dump for 24 popular "
            "network-parsing libraries, intersected with the project's DI CWE set "
            "(including the April 2026 auth-bypass widening). KEV / Metasploit / "
            "ExploitDB outcome flags come from cross-referencing CISA KEV catalog "
            "and the cached exploit-source caches."
        ),
        "methodology": {
            "np_filter": "OSV CWE classifier output 'parsing' (vs 'non_parsing' or 'ambiguous')",
            "di_filter": f"CWE present in DI set of {len(DI_CWES)} CWEs (see scripts/build_seven_year_npdi.py)",
            "outcome_sources": ["CISA KEV", "Metasploit (via cached query)", "ExploitDB (via cached query)"],
            "in_manifest_definition": (
                "Package matches the 60-package Spring Boot enterprise manifest "
                "from analysis-scripts/spring_manifest_analysis.py"
            ),
            "known_limitations": [
                "Cached OSV detail covers 24 packages out of the 60-package manifest. "
                "Only 3 manifest packages have OSV detail cached: jackson-databind, "
                "tomcat-embed-core, spring-webmvc. The broader scope (24 popular "
                "network-parsing libraries) is more representative for cross-package "
                "trend analysis.",
                "OSV event IDs without an embedded CVE are matched via summary regex; "
                "events with no detectable CVE have all outcome flags False and a "
                "null EPSS score — they may be in KEV via a CVE alias not in the cache.",
                "EPSS scores only present for the 16 12-month-window NP+DI events; "
                "older events (2018-2024) do not have cached EPSS.",
                "Date field absent from OSV cache — events are ordered by "
                "(in_kev, package, cwe) for stable diffing.",
            ],
        },
        "input_sources": {
            "osv_cwe_results_sha256_16": osv_sha,
            "kev_snapshot": "data/kev-snapshot-2026-04-23.json",
            "kev_snapshot_sha256_16": kev_sha,
            "di_cwe_count": len(DI_CWES),
        },
        "summary": summary,
        "events": events,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "seven-year-npdi-events.json"
    new = render_dataset()

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        # Compare events + summary; ignore generated_at timestamp
        for k in ("events", "summary", "input_sources", "methodology", "description"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    s = new["summary"]
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  events:                  {s['total_events']}")
    print(f"  in manifest scope:       {s['in_manifest_count']}")
    print(f"  in KEV (any scope):      {s['in_kev_count']}")
    print(f"  in KEV + manifest:       {s['in_kev_and_manifest_count']}")
    print(f"  in Metasploit:           {s['in_metasploit_count']}")
    print(f"  in ExploitDB:            {s['in_exploitdb_count']}")
    print(f"  with detectable CVE:     {s['with_cve_id']}")
    print(f"  by ecosystem:            {s['by_ecosystem']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
