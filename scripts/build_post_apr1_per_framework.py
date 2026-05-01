#!/usr/bin/env python3
"""
Build the post-2026-04-01 per-framework dataset that backs the dashboard
"Live tracker (Apr 1 forward)" chart.

For each of our 5 manifests (Spring Boot, Node.js/Express, Django/Python,
Netty, Real-world Java enterprise), it tallies — over events with
disclosure date >= 2026-04-01 — three things using the canonical 7-day
clustering rule:

  1. all_ch_clusters     — patch events from any C/H CVE in manifest
  2. npdi_clusters       — patch events from NP+DI CVEs (the model fires)
  3. exploited_count     — distinct CVEs that have shown up in
                           CISA KEV / Metasploit / ExploitDB

Sources reused as-is from the canonical 12-month per-framework builder:
  - cached-data/periodicity/spring_periodicity_data.json
  - cached-data/periodicity/multi_framework_periodicity.json
  - data/_netty-osv-cache.json
  - data/_osv-alias-cache.json    (GHSA → CVE mapping)
  - data/kev-snapshot-2026-05-01.json
  - data/_metasploit-cves.json
  - data/_exploitdb-cves.json
  - data/seven-year-manifest-events.json  (Real-world Java enterprise; 58 packages,
                                           includes ActiveMQ + Camel layered onto
                                           the Spring Boot starter)

Output:
  data/post-apr1-per-framework.json
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = Path("/sessions/bold-nice-euler/mnt/vulnerability analysis/cached-data")
CUTOFF = "2026-04-01"

# ── DI CWE set (frozen 2026-05-01) ────────────────────────────────
DI_CWES = {
    22, 23, 35, 73, 74, 77, 78, 79, 89, 90, 91, 93, 94, 95, 96, 97,
    113, 116, 287, 289, 306, 345, 444, 502, 611, 693, 776, 863, 917,
    918, 1321,
    # Also accepted historically by the 12-month NP+DI corpus (kept for
    # parity with twelve-month-per-framework.json):
    1336, 36, 98, 1236,
}


def _cluster_count(dates: list[str], window_days: int = 7) -> int:
    """Patch-event clusters under the 7-day window rule. Matches
    scripts/build_hacker_tier_data.py:_cluster_count."""
    if not dates:
        return 0
    parsed = sorted(dt.datetime.strptime(d, "%Y-%m-%d") for d in dates)
    clusters = 1
    for prev, cur in zip(parsed, parsed[1:]):
        if (cur - prev).days > window_days:
            clusters += 1
    return clusters


def _is_npdi(event: dict) -> bool:
    """Return True if event is NP and at least one CWE is in the DI set."""
    if not event.get("is_np"):
        return False
    for c in event.get("cwes") or []:
        try:
            n = int(str(c).removeprefix("CWE-"))
        except ValueError:
            continue
        if n in DI_CWES:
            return True
    return False


def load_spring() -> dict:
    return json.load(open(CACHE / "periodicity" / "spring_periodicity_data.json"))


def load_multi() -> dict:
    return json.load(open(CACHE / "periodicity" / "multi_framework_periodicity.json"))


def load_netty() -> dict:
    return json.load(open(REPO / "data" / "_netty-osv-cache.json"))


def load_real_java() -> list[dict]:
    """Real-world Java enterprise = the 58-pkg seven-year manifest.

    Schema is per-CVE rather than per-GHSA-package and uses 'published'
    rather than 'date'. We normalize into the same shape collect_events()
    expects (date, vuln_id, package, severity, is_np, is_di, cwes).
    """
    sm = json.load(open(REPO / "data" / "seven-year-manifest-events.json"))
    out = []
    for e in sm["events"]:
        if (e.get("published") or "") < CUTOFF:
            continue
        # If multiple packages, attribute to the first NP package if any,
        # else first listed; collapses one-CVE-affects-many-pkgs to a
        # single deployment-event row.
        pkgs = e.get("packages") or []
        roles = e.get("package_roles") or []
        chosen = None
        for p, r in zip(pkgs, roles):
            if r == "NP":
                chosen = p; break
        if chosen is None and pkgs:
            chosen = pkgs[0]
        out.append({
            "date": e["published"],
            "vuln_id": e.get("osv_id") or e["cve"],
            "_cve": e["cve"],
            "package": (chosen or "").split(":")[-1],
            "severity": e.get("severity"),
            "is_np": e.get("is_np", False),
            "cwes": e.get("cwes") or [],
            # Pre-resolved exploit signals (don't need GHSA→CVE roundtrip)
            "_in_kev": e.get("in_kev", False),
            "_in_msf": e.get("in_metasploit", False),
            "_in_edb": e.get("in_exploitdb", False),
        })
    return sorted(out, key=lambda e: e["date"])


def load_alias_cache() -> dict:
    return json.load(open(REPO / "data" / "_osv-alias-cache.json"))


def load_kev_cves() -> set[str]:
    kev = json.load(open(REPO / "data" / "kev-snapshot-2026-05-01.json"))
    return {v["cveID"] for v in kev["vulnerabilities"]}


def load_msf_cves() -> set[str]:
    p = REPO / "data" / "_metasploit-cves.json"
    if not p.exists():
        return set()
    raw = json.load(open(p))
    if isinstance(raw, list):
        return set(raw)
    if isinstance(raw, dict):
        return set(raw.keys())
    return set()


def load_edb_cves() -> set[str]:
    p = REPO / "data" / "_exploitdb-cves.json"
    if not p.exists():
        return set()
    raw = json.load(open(p))
    if isinstance(raw, list):
        return set(raw)
    if isinstance(raw, dict):
        return set(raw.keys())
    return set()


def ghsa_to_cves(ghsa: str, alias_cache: dict) -> list[str]:
    rec = alias_cache.get(ghsa)
    if not rec:
        return []
    return [a for a in rec.get("aliases", []) if a.startswith("CVE-")]


def collect_events(framework_label: str, raw_events: list[dict]) -> list[dict]:
    """Filter to >= CUTOFF, normalize to a per-event dict."""
    out = []
    for e in raw_events:
        if e["date"] < CUTOFF:
            continue
        out.append(e)
    return sorted(out, key=lambda e: e["date"])


def summarize(label: str, events: list[dict], alias_cache: dict,
              kev_cves: set[str], msf_cves: set[str], edb_cves: set[str]) -> dict:
    all_dates = [e["date"] for e in events]
    npdi_dates = [e["date"] for e in events if _is_npdi(e)]

    # For each event, resolve exploit signals. Real-world Java rows arrive
    # with pre-resolved _in_kev/_in_msf/_in_edb (the seven-year manifest
    # already did the lookup); GHSA rows go through alias_cache → CVE.
    exploited = []
    enriched = []
    for e in events:
        if "_in_kev" in e:
            kev_hit = bool(e["_in_kev"])
            msf_hit = bool(e["_in_msf"])
            edb_hit = bool(e["_in_edb"])
            cves = [e["_cve"]] if e.get("_cve") else []
        else:
            cves = ghsa_to_cves(e["vuln_id"], alias_cache)
            kev_hit = any(c in kev_cves for c in cves)
            msf_hit = any(c in msf_cves for c in cves)
            edb_hit = any(c in edb_cves for c in cves)
        if kev_hit or msf_hit or edb_hit:
            exploited.append({
                "date": e["date"],
                "ghsa": e["vuln_id"],
                "cves": cves,
                "package": e["package"],
                "in_kev": kev_hit,
                "in_msf": msf_hit,
                "in_edb": edb_hit,
            })
        enriched.append({
            "date": e["date"],
            "ghsa": e["vuln_id"],
            "cves": cves,
            "package": e["package"],
            "severity": e.get("severity"),
            "is_np": e.get("is_np"),
            "is_di": _is_npdi(e),
            "cwes": e.get("cwes") or [],
            "exploited": kev_hit or msf_hit or edb_hit,
        })

    return {
        "label": label,
        "all_ch_event_count": len(events),
        "all_ch_clusters": _cluster_count(list(set(all_dates))),
        "npdi_event_count": len(npdi_dates),
        "npdi_clusters": _cluster_count(list(set(npdi_dates))),
        "exploited_count": len(exploited),
        "exploited_events": exploited,
        "events": enriched,
    }


def main() -> None:
    spring = load_spring()
    multi = load_multi()
    netty = load_netty()
    aliases = load_alias_cache()
    kev_cves = load_kev_cves()
    msf_cves = load_msf_cves()
    edb_cves = load_edb_cves()

    spring_evts = collect_events("Spring Boot", spring["all_events"])
    nodejs_evts = collect_events("Node.js/Express", multi["nodejs"]["all_events"])
    django_evts = collect_events("Django/Python", multi["django"]["all_events"])
    netty_evts = collect_events("Netty", netty["all_events"])
    real_java_evts = load_real_java()

    frameworks = {
        "spring":    summarize("Spring Boot",        spring_evts,    aliases, kev_cves, msf_cves, edb_cves),
        "nodejs":    summarize("Node.js/Express",    nodejs_evts,    aliases, kev_cves, msf_cves, edb_cves),
        "django":    summarize("Django/Python",      django_evts,    aliases, kev_cves, msf_cves, edb_cves),
        "netty":     summarize("Netty",              netty_evts,     aliases, kev_cves, msf_cves, edb_cves),
        "real_java": summarize("Real-world Java",    real_java_evts, aliases, kev_cves, msf_cves, edb_cves),
    }

    out = {
        "generated_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cutoff": CUTOFF,
        "snapshot_through": "2026-04-30",  # cached-data + KEV freshness
        "description": (
            "Live tracker — events with disclosure date >= 2026-04-01 "
            "for the five manifests (4 modeled + 1 real-world Java enterprise), "
            "with exploit cross-reference. Patch-event counts use the canonical "
            "7-day clustering rule."
        ),
        "methodology": {
            "cluster_window_days": 7,
            "cluster_rule": "Maximal run of dates where adjacent pairs "
                            "sit within 7 days (matches "
                            "scripts/build_hacker_tier_data.py:_cluster_count).",
            "di_cwe_set_frozen_2026_05_01": sorted(DI_CWES),
            "exploit_signals": ["CISA KEV", "Metasploit", "ExploitDB"],
        },
        "frameworks": frameworks,
        "summary": {
            "labels": [frameworks[k]["label"] for k in ("spring", "nodejs", "django", "netty", "real_java")],
            "all_ch_clusters":  [frameworks[k]["all_ch_clusters"]  for k in ("spring", "nodejs", "django", "netty", "real_java")],
            "npdi_clusters":    [frameworks[k]["npdi_clusters"]    for k in ("spring", "nodejs", "django", "netty", "real_java")],
            "exploited_counts": [frameworks[k]["exploited_count"]  for k in ("spring", "nodejs", "django", "netty", "real_java")],
        },
    }

    out_path = REPO / "data" / "post-apr1-per-framework.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {out_path}")
    print(json.dumps(out["summary"], indent=2))


if __name__ == "__main__":
    main()
