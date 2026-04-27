#!/usr/bin/env python3
"""
Compute EPSS-marginal patch event counts for the 7-year manifest backtest.

The §15 EPSS comparison on docs/periodicity.html previously treated EPSS as a
standalone strategy. This script answers the more honest question: if the
operator is already running a structure model (NP+DI, NP+DI+DQ, or hacker S+A)
that triggers manifest-wide rebuilds, how many ADDITIONAL rebuilds does EPSS
add on top of the model?

Floor-sweep model (per project memo)
------------------------------------
When a model trigger fires for any CVE in a manifest's "family", a rebuild
rolls every dependency in that manifest to its latest version — incidentally
picking up patches for adjacent CVEs that have already been patched but
haven't yet crossed an EPSS threshold.

So an EPSS-flagged CVE X is absorbed for free iff:

    disclosure_date(X)  <=  some_model_trigger_date  <  epss_cross_date(X)

Where `epss_cross_date(X)` is the first day EPSS crossed the threshold
(0.10 or 0.50). If no model trigger fires in that window, the EPSS event
is "marginal" — it forces a rebuild EPSS would not have caught for free.

Disclosure date is used as a proxy for fix-release date (per project memo:
"most major libraries ship a patch within days of CVD"). This is an
approximation — for some CVEs the upstream patch ships days/weeks after
NVD publication, which would shrink the absorb-able window slightly. The
direction of error is to over-credit absorption.

Inputs
------
  - data/seven-year-manifest-events.json (175 events, NP+DI/exploited flags,
    publication dates)
  - data/hacker-tiers.json (per-CVE S/A/B/C/D)
  - FIRST.org EPSS API (live HTTP query, cached locally)

Outputs
-------
  - data/epss-marginal.json — full per-CVE breakdown + summary table
  - Stdout: human-readable comparison

Usage
-----
    python3 scripts/compute_epss_marginal.py            # compute + write
    python3 scripts/compute_epss_marginal.py --check    # exit 1 if stale
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATASET_OUT = REPO / "data" / "epss-marginal.json"
EPSS_CACHE = REPO / "data" / "_epss-historical-cache.json"
KEV_SNAPSHOT = REPO / "data" / "kev-snapshot-2026-04-26.json"
EXPLOITDB_CSV_CACHE = REPO / "data" / "_exploitdb-publish-dates.json"
EXPLOITDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)

EPSS_API = "https://api.first.org/data/v1/epss"

# Probe dates (offsets from publication) used to bracket the crossing day.
# We don't need exact day, just whether any model trigger fired before the
# crossing date. Probing at 1, 7, 30, 90, 180, 365, 730 days post-publication
# plus current is dense enough for the question we're answering.
PROBE_OFFSETS_DAYS = [1, 3, 7, 14, 30, 60, 90, 180, 365, 730, 1095, 1460, 2190, 2920]

# Thresholds the §15 table uses
THRESHOLDS = [0.10, 0.50]

# Hacker tiers we rebuild on (S and A)
HACKER_REBUILD_TIERS = {"S", "A"}


# --------------------------------------------------------------------------
# EPSS API — query with local cache
# --------------------------------------------------------------------------

def load_epss_cache() -> dict:
    if EPSS_CACHE.exists():
        return json.load(open(EPSS_CACHE))
    return {}


def save_epss_cache(cache: dict) -> None:
    EPSS_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True))


def query_epss(cve: str, date: str, cache: dict) -> float | None:
    """Query EPSS for a single CVE on a single date. Returns None if no data."""
    key = f"{cve}@{date}"
    if key in cache:
        v = cache[key]
        return None if v is None else float(v)

    url = f"{EPSS_API}?cve={urllib.parse.quote(cve)}&date={date}"
    backoff = 1.0
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                payload = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code == 422:
                # Date before EPSS coverage for this CVE — cache as None and stop.
                cache[key] = None
                return None
            if attempt == 2:
                print(f"  WARN: {cve}@{date} HTTP {e.code}: {e}", file=sys.stderr)
                cache[key] = None
                return None
            time.sleep(backoff)
            backoff *= 2
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 2:
                print(f"  WARN: {cve}@{date} net error: {e}", file=sys.stderr)
                cache[key] = None
                return None
            time.sleep(backoff)
            backoff *= 2

    data = payload.get("data", [])
    if not data:
        cache[key] = None
        return None
    epss = float(data[0].get("epss", 0))
    cache[key] = epss
    return epss


# --------------------------------------------------------------------------
# Crossing-day estimation
# --------------------------------------------------------------------------

def find_crossing_date_multi(cve: str, pub_date: str, thresholds: list[float],
                              cache: dict, today: dt.date) -> dict[float, str | None]:
    """
    For each threshold in `thresholds`, find the first probe date at which
    EPSS crosses (>=) that threshold. Returns {threshold: iso_date_or_None}.

    Strategy: query at PROBE_OFFSETS_DAYS post-publication (capped at today).
    We probe ALL points eagerly so we can answer all thresholds in one pass
    (saves API calls vs separate per-threshold passes).

    We DON'T bisect to find the exact day; we use the upper-bound probe date
    as a conservative approximation. This OVER-credits absorption (because if
    a model trigger fires after the true crossing date but before the upper-
    bound probe, we incorrectly call it absorbed). Mitigation: probe density
    is dense early (1, 3, 7, 14, 30 days) where most rapid risers cross.

    Optimization: skip current-date probe if we have a recent (today-30 days)
    score above all thresholds. Skip future probes if all thresholds already
    crossed.
    """
    pub = dt.date.fromisoformat(pub_date)
    probe_dates = []
    for offset in PROBE_OFFSETS_DAYS:
        probe = pub + dt.timedelta(days=offset)
        if probe > today:
            break
        probe_dates.append(probe.isoformat())
    probe_dates.append(today.isoformat())
    # Dedupe & sort
    probe_dates = sorted(set(probe_dates))

    crossings: dict[float, str | None] = {thr: None for thr in thresholds}
    remaining = set(thresholds)

    none_streak = 0
    for probe in probe_dates:
        if not remaining:
            break
        epss = query_epss(cve, probe, cache)
        if epss is None:
            none_streak += 1
            # If 5 consecutive probes return None (CVE pre-dates EPSS at all
            # those points), give up — no need to keep probing.
            # We still try the final today probe via the loop continuing.
            if none_streak >= 5:
                # Skip ahead to current date; we already cached the failures.
                continue
            continue
        none_streak = 0
        # Check each remaining threshold
        crossed_now = [thr for thr in remaining if epss >= thr]
        for thr in crossed_now:
            crossings[thr] = probe
            remaining.discard(thr)

    return crossings


# --------------------------------------------------------------------------
# Exploit-release date sources (KEV / ExploitDB / Metasploit)
# --------------------------------------------------------------------------

# Cohort: 8 in-scope exploited CVEs in the 7-year manifest
IN_SCOPE_8 = [
    ("CVE-2021-44228", "Log4Shell"),
    ("CVE-2021-45046", "Log4Shell follow-on"),
    ("CVE-2022-22965", "Spring4Shell"),
    ("CVE-2021-39144", "XStream RCE"),
    ("CVE-2025-24813", "Tomcat partial-PUT"),
    ("CVE-2020-1938",  "Ghostcat"),
    ("CVE-2026-34197", "ActiveMQ Jolokia"),
    ("CVE-2019-0232",  "Tomcat CGI"),
]

# EPSS public coverage started ~April 2021. CVEs disclosed before that could
# not have been flagged by EPSS in real time, so we honestly mark them as
# "EPSS would never have caught" rather than letting the post-hoc 2021 cross-
# date polute the average.
PRE_EPSS_CUTOFF = dt.date(2021, 4, 14)


def load_kev_dateadded() -> dict[str, str]:
    """Map CVE -> KEV dateAdded ('YYYY-MM-DD'). KEV listing is treated as a
    proxy for 'actively exploited in the wild'."""
    if not KEV_SNAPSHOT.exists():
        return {}
    kev = json.load(open(KEV_SNAPSHOT))
    out = {}
    for v in kev.get("vulnerabilities", []):
        cve = v.get("cveID")
        d = v.get("dateAdded")
        if cve and d:
            out[cve] = d
    return out


def load_exploitdb_dates(cves: list[str]) -> dict[str, str]:
    """For each CVE return the earliest ExploitDB date_published. Cached on
    disk under data/_exploitdb-publish-dates.json keyed by CVE.

    The on-disk csv cache (data/_exploitdb-cves.json) only stores CVE IDs,
    not publish dates. We fetch the upstream csv once, parse out the earliest
    date_published per CVE in the cohort, and cache the slim mapping for
    future runs.
    """
    if EXPLOITDB_CSV_CACHE.exists():
        cached = json.load(open(EXPLOITDB_CSV_CACHE))
        if all(c in cached for c in cves):
            return {c: cached[c] for c in cves if cached.get(c)}

    # Fetch upstream CSV
    import csv
    import io
    print("  fetching ExploitDB upstream CSV for publish dates...", file=sys.stderr)
    try:
        with urllib.request.urlopen(EXPLOITDB_CSV_URL, timeout=30) as r:
            raw = r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  WARN: ExploitDB fetch failed: {e}", file=sys.stderr)
        return json.load(open(EXPLOITDB_CSV_CACHE)) if EXPLOITDB_CSV_CACHE.exists() else {}

    cohort_set = set(cves)
    earliest: dict[str, str] = {}
    rdr = csv.DictReader(io.StringIO(raw))
    for row in rdr:
        codes = row.get("codes") or ""
        if "CVE-" not in codes:
            continue
        date_pub = row.get("date_published") or row.get("date_added") or ""
        if not date_pub:
            continue
        for token in codes.replace(",", ";").split(";"):
            token = token.strip()
            if token in cohort_set:
                prev = earliest.get(token)
                if prev is None or date_pub < prev:
                    earliest[token] = date_pub
    # Persist (None for missing so subsequent runs don't re-fetch)
    cache = {c: earliest.get(c) for c in cves}
    EXPLOITDB_CSV_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True))
    return {c: v for c, v in cache.items() if v}


def compute_t_exploit(cves: list[str]) -> dict[str, dict[str, str | None]]:
    """For each CVE, return {'kev': iso_or_none, 'exploitdb': iso_or_none,
    'earliest': iso_or_none, 'source': 'kev'|'exploitdb'|None}.

    Metasploit module-add date isn't available cheaply on disk (the cached
    json stores CVE -> module-path mapping with mod_time being last-commit
    time, not first-commit). Module presence alone isn't dated, so we omit
    Metasploit from the priority list. KEV dateAdded usually predates
    Metasploit module publication anyway; in our cohort every CVE except
    Tomcat CGI is in KEV, and Tomcat CGI has an ExploitDB entry that gives
    a reliable date.
    """
    kev_dates = load_kev_dateadded()
    edb_dates = load_exploitdb_dates(cves)

    out = {}
    for cve in cves:
        kev = kev_dates.get(cve)
        edb = edb_dates.get(cve)
        candidates = [(d, src) for d, src in [(kev, "kev"), (edb, "exploitdb")] if d]
        candidates.sort()
        earliest = candidates[0] if candidates else None
        out[cve] = {
            "kev": kev,
            "exploitdb": edb,
            "earliest": earliest[0] if earliest else None,
            "source": earliest[1] if earliest else None,
        }
    return out


# --------------------------------------------------------------------------
# 7-day patch-event clustering
# --------------------------------------------------------------------------

def cluster_dates(iso_dates: list[str], window_days: int = 7) -> list[list[str]]:
    """Group ISO dates into clusters where consecutive dates within
    `window_days` of the previous CVE belong to the same cluster.
    Returns list of clusters (each cluster is a list of dates)."""
    if not iso_dates:
        return []
    sorted_dates = sorted(set(iso_dates))
    clusters = [[sorted_dates[0]]]
    for d in sorted_dates[1:]:
        prev = dt.date.fromisoformat(clusters[-1][-1])
        cur = dt.date.fromisoformat(d)
        if (cur - prev).days <= window_days:
            clusters[-1].append(d)
        else:
            clusters.append([d])
    return clusters


# --------------------------------------------------------------------------
# Main computation
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the file.")
    ap.add_argument("--no-network", action="store_true",
                    help="Use only cached EPSS data; fail if uncached lookups needed.")
    args = ap.parse_args()

    today = dt.date.today()

    # Load events
    manifest = json.load(open(REPO / "data" / "seven-year-manifest-events.json"))
    events = manifest["events"]
    hacker_tiers = json.load(open(REPO / "data" / "hacker-tiers.json"))["tiers"]

    # NP+DI trigger dates (manifest-wide floor-sweep on any NP+DI event)
    npdi_dates = sorted({e["published"] for e in events
                         if e.get("is_np") and e.get("is_di") and e.get("published")})

    # NP+DI+DQ adds the AI-rescue events. Per the audit trail
    # (data/INTEGRATED-PAGE-AUDIT-TRAIL.md), the DQ rescues on the manifest
    # are the 3 NP-only-not-DI exploited events: Ghostcat, Tomcat partial-PUT,
    # ActiveMQ Jolokia. We include them as additional trigger dates.
    DQ_RESCUE_CVES = {
        "CVE-2020-1938",   # Ghostcat
        "CVE-2025-24813",  # Tomcat partial-PUT
        "CVE-2026-34197",  # ActiveMQ Jolokia
        "CVE-2023-46604",  # ActiveMQ deser (also DQ-rescued in spirit)
    }
    dq_dates = sorted({e["published"] for e in events
                       if e.get("cve") in DQ_RESCUE_CVES and e.get("published")})
    npdi_dq_dates = sorted(set(npdi_dates) | set(dq_dates))

    # Hacker S+A trigger dates
    hacker_sa_cves = {cve for cve, info in hacker_tiers.items()
                      if info.get("tier") in HACKER_REBUILD_TIERS}
    hacker_dates = sorted({e["published"] for e in events
                           if e.get("cve") in hacker_sa_cves and e.get("published")})

    # ----------- EPSS data gathering -----------
    cache = load_epss_cache()
    cve_pubs: dict[str, str] = {}
    for ev in events:
        if ev.get("cve") and ev.get("published"):
            # Multiple events per CVE possible (collapse to first published).
            existing = cve_pubs.get(ev["cve"])
            if existing is None or ev["published"] < existing:
                cve_pubs[ev["cve"]] = ev["published"]

    print(f"Querying EPSS for {len(cve_pubs)} CVEs across {len(THRESHOLDS)} thresholds...",
          file=sys.stderr)

    # Per-CVE crossing dates (or None if never crossed)
    crossings: dict[str, dict[str, str | None]] = {}
    for i, (cve, pub) in enumerate(sorted(cve_pubs.items()), 1):
        if i % 10 == 0:
            print(f"  progress: {i}/{len(cve_pubs)} (cache: {len(cache)} entries)",
                  file=sys.stderr)
            save_epss_cache(cache)  # checkpoint every 10 CVEs
        cross_per_thr = find_crossing_date_multi(cve, pub, THRESHOLDS, cache, today)
        crossings[cve] = {f"{thr}": cross_per_thr[thr] for thr in THRESHOLDS}

    save_epss_cache(cache)

    # ----------- Marginal computation -----------
    # For each (threshold, model) pair, count:
    #   - Standalone EPSS triggers (CVEs that crossed threshold by today)
    #   - Marginal EPSS triggers (those whose crossing date is BEFORE any
    #     model trigger in [pub, cross) — i.e., NOT absorbed by floor-sweep)
    #
    # Patch events: 7-day cluster the standalone or marginal trigger dates.

    models = {
        "NP+DI": npdi_dates,
        "NP+DI+DQ": npdi_dq_dates,
        "Hacker S+A": hacker_dates,
    }

    summary: dict = {}
    per_cve: dict = {}

    for thr in THRESHOLDS:
        thr_key = f"epss_ge_{int(thr*100):02d}"
        standalone_dates = []
        absorbed_by: dict[str, dict[str, str | None]] = {}
        for cve, pub in sorted(cve_pubs.items()):
            cross = crossings[cve][f"{thr}"]
            if cross is None:
                continue
            standalone_dates.append(cross)

            absorbed_by[cve] = {"pub": pub, "cross": cross}
            for model_name, model_dates in models.items():
                # Find any model trigger in [pub, cross). If yes -> absorbed.
                # disclosure_date itself counts as same-day (could be same
                # advisory date), so we use `pub <= T < cross`.
                absorbed = any(pub <= t < cross for t in model_dates)
                absorbed_by[cve][f"absorbed_by_{model_name}"] = absorbed

        # Cluster standalone dates
        clusters = cluster_dates(standalone_dates)
        standalone_pe = len(clusters)
        standalone_raw = len(standalone_dates)

        thr_summary = {
            "threshold": thr,
            "standalone_raw_cves": standalone_raw,
            "standalone_patch_events": standalone_pe,
            "marginal": {}
        }

        for model_name in models:
            marginal_dates = []
            absorbed_count = 0
            for cve, info in absorbed_by.items():
                if info[f"absorbed_by_{model_name}"]:
                    absorbed_count += 1
                else:
                    marginal_dates.append(info["cross"])
            marginal_clusters = cluster_dates(marginal_dates)
            thr_summary["marginal"][model_name] = {
                "absorbed_cves": absorbed_count,
                "marginal_cves": len(marginal_dates),
                "marginal_patch_events": len(marginal_clusters),
                "absorption_rate": (
                    f"{absorbed_count}/{standalone_raw}"
                    if standalone_raw else "0/0"
                ),
            }

        summary[thr_key] = thr_summary
        per_cve[thr_key] = absorbed_by

    # ----------- Hacker S+A row on the 8 in-scope exploited CVEs -----------
    # The §15 EPSS table tracks 8 in-scope exploited CVEs. Hacker S+A is a
    # CVE-structure judgment that doesn't time-vary, so any S/A-graded CVE
    # is "caught at day 0". The patch-event count is the 7-day-clustered
    # date count for those S/A events.
    in_scope_8 = [
        "CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965",
        "CVE-2021-39144", "CVE-2025-24813", "CVE-2020-1938",
        "CVE-2026-34197", "CVE-2019-0232",
    ]
    sa_caught = []
    sa_dates = []
    for cve in in_scope_8:
        tier = hacker_tiers.get(cve, {}).get("tier")
        pub = cve_pubs.get(cve)
        caught = tier in HACKER_REBUILD_TIERS
        if caught and pub:
            sa_caught.append(cve)
            sa_dates.append(pub)

    # All hacker S+A events on the manifest (not just exploited) are the
    # rebuild trigger set. The 8-of-8 question: how many of the 8 in-scope
    # exploited CVEs does the discriminator catch on each day-X horizon?
    # Tier is set at disclosure → all-or-nothing on day 0.
    hacker_caught_n = len(sa_caught)
    hacker_total_pe = len(cluster_dates(hacker_dates))

    summary["hacker_sa_in_scope_8"] = {
        "day_0": f"{hacker_caught_n}/8",
        "day_7": f"{hacker_caught_n}/8",
        "day_30": f"{hacker_caught_n}/8",
        "eventually": f"{hacker_caught_n}/8",
        "total_patch_events_on_manifest": hacker_total_pe,
        "caught_cves": sa_caught,
        "missed_cves": [c for c in in_scope_8 if c not in sa_caught],
    }

    # ---------- TIMING COMPARISON: model vs EPSS, and caught-before-exploit ----------
    # For each in-scope CVE:
    #   t_model    = pub date (NP+DI+DQ catches all 8 on disclosure day; that's
    #                the model the §15 narrative recommends as the default)
    #   t_epss(thr)= first probe date EPSS crossed >= thr (from `crossings`)
    #   t_exploit  = earliest of (KEV dateAdded, ExploitDB publish date)
    # delta_days(thr) = t_epss(thr) - t_model — how many days earlier the model
    #                   fired vs EPSS at that threshold.
    # caught_before_exploit(t_fire) = t_fire + 30d < t_exploit

    PATCH_DAYS = 30
    cohort_cves = [c for c, _ in IN_SCOPE_8]
    t_exploit_data = compute_t_exploit(cohort_cves)

    def parse(d: str | None) -> dt.date | None:
        return dt.date.fromisoformat(d) if d else None

    def caught_before(t_fire: dt.date | None, t_exp: dt.date | None) -> bool:
        if t_fire is None or t_exp is None:
            return False
        return (t_fire + dt.timedelta(days=PATCH_DAYS)) < t_exp

    timing_per_cve = []
    deltas_10: list[int] = []
    deltas_50: list[int] = []
    pre_epss_cves: list[str] = []
    y_model = 0
    y_epss10 = 0
    y_epss50 = 0

    for cve, name in IN_SCOPE_8:
        pub = cve_pubs.get(cve)
        cross10 = crossings.get(cve, {}).get(f"{0.10}")
        cross50 = crossings.get(cve, {}).get(f"{0.50}")
        te = t_exploit_data.get(cve, {}).get("earliest")
        te_src = t_exploit_data.get(cve, {}).get("source")

        # Pre-EPSS detection: if disclosure_date is before EPSS public coverage
        # AND the recorded EPSS-cross date is >= 1 year past disclosure (a
        # tell-tale of "EPSS started scoring this when coverage began, not in
        # real time"), mark it pre-EPSS.
        is_pre_epss = False
        pub_d = parse(pub)
        if pub_d and pub_d < PRE_EPSS_CUTOFF:
            is_pre_epss = True
            pre_epss_cves.append(cve)

        # Model timing: t_model = pub (NP+DI+DQ catches all 8 on disclosure day)
        t_model_d = pub_d
        cross10_d = parse(cross10)
        cross50_d = parse(cross50)
        te_d = parse(te)

        d10 = (cross10_d - t_model_d).days if (cross10_d and t_model_d) else None
        d50 = (cross50_d - t_model_d).days if (cross50_d and t_model_d) else None

        # Caught-before-exploit
        cm = caught_before(t_model_d, te_d)
        # For pre-EPSS, EPSS would not have flagged in real time at any threshold.
        if is_pre_epss:
            ce10 = False
            ce50 = False
        else:
            ce10 = caught_before(cross10_d, te_d)
            ce50 = caught_before(cross50_d, te_d)

        if cm: y_model += 1
        if ce10: y_epss10 += 1
        if ce50: y_epss50 += 1

        # Add to averages only when EPSS coverage was real-time-applicable
        if not is_pre_epss:
            if d10 is not None:
                deltas_10.append(d10)
            if d50 is not None:
                deltas_50.append(d50)

        timing_per_cve.append({
            "cve": cve,
            "name": name,
            "pub": pub,
            "t_model": pub,                       # NP+DI+DQ fires day 0
            "t_epss_10": cross10,
            "t_epss_50": cross50,
            "delta_days_epss_10": d10,
            "delta_days_epss_50": d50,
            "t_exploit": te,
            "t_exploit_source": te_src,
            "kev_date_added": t_exploit_data.get(cve, {}).get("kev"),
            "exploitdb_publish": t_exploit_data.get(cve, {}).get("exploitdb"),
            "is_pre_epss": is_pre_epss,
            "model_caught_before_exploit": cm,
            "epss_10_caught_before_exploit": ce10,
            "epss_50_caught_before_exploit": ce50,
        })

    avg_d10 = (sum(deltas_10) / len(deltas_10)) if deltas_10 else None
    avg_d50 = (sum(deltas_50) / len(deltas_50)) if deltas_50 else None

    summary["timing_comparison"] = {
        "patch_cycle_days": PATCH_DAYS,
        "cohort_size": len(IN_SCOPE_8),
        "model_used_for_t_model": "NP+DI+DQ (catches all 8 on disclosure day)",
        "t_exploit_definition": (
            "earliest of (KEV dateAdded, ExploitDB publish date). "
            "Metasploit module-add date is not available cheaply on disk "
            "(the cached msf json gives CVE->module-path with mod_time = last "
            "commit, not first); KEV dateAdded usually predates module "
            "publication anyway. CVEs without KEV listing AND without an "
            "ExploitDB entry have no t_exploit and are excluded from the "
            "caught-before-exploit headline."
        ),
        "pre_epss_cutoff": PRE_EPSS_CUTOFF.isoformat(),
        "pre_epss_cves": pre_epss_cves,
        "pre_epss_handling": (
            "CVEs disclosed before EPSS public coverage (~April 2021) "
            "could not have been flagged by EPSS in real time. They are "
            "excluded from the days-faster average and counted as 'EPSS "
            "would never have caught in real time' in the caught-before-"
            "exploit tally."
        ),
        "avg_days_faster_vs_epss_10": avg_d10,
        "avg_days_faster_vs_epss_50": avg_d50,
        "avg_n_with_epss_coverage": len(IN_SCOPE_8) - len(pre_epss_cves),
        "caught_before_exploit": {
            "model": f"{y_model}/{len(IN_SCOPE_8)}",
            "epss_ge_10": f"{y_epss10}/{len(IN_SCOPE_8)}",
            "epss_ge_50": f"{y_epss50}/{len(IN_SCOPE_8)}",
            "marginal_model_minus_epss_10": y_model - y_epss10,
            "marginal_model_minus_epss_50": y_model - y_epss50,
        },
        "per_cve": timing_per_cve,
    }

    # ----------- Compose output -----------
    output = {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "EPSS-marginal-on-top-of-model patch event counts for the 7-year "
            "manifest backtest (175 C/H events). Floor-sweep model: any model "
            "trigger fires a manifest-wide rebuild that absorbs adjacent "
            "patched CVEs whose EPSS hasn't yet crossed the action threshold."
        ),
        "methodology": {
            "manifest_events_source": "data/seven-year-manifest-events.json",
            "hacker_tier_source": "data/hacker-tiers.json",
            "epss_source": "FIRST.org EPSS API (https://api.first.org/data/v1/epss)",
            "floor_sweep_rule": (
                "EPSS-flagged CVE X is absorbed iff disclosure_date(X) <= T < "
                "epss_cross_date(X) for some model trigger date T."
            ),
            "approximation_notes": [
                "Disclosure date used as proxy for fix-release date.",
                "Crossing date approximated by first-positive probe at offsets "
                f"{PROBE_OFFSETS_DAYS} days post-publication. Conservative (over-credits absorption).",
                "DQ rescues identified manually: Ghostcat, Tomcat partial-PUT, "
                "ActiveMQ Jolokia, ActiveMQ deser (per integrated-page audit trail).",
                "7-day clustering applied to compute patch events from raw dates.",
            ],
            "thresholds": THRESHOLDS,
        },
        "model_trigger_counts": {
            "NP+DI": {
                "raw_dates": len(npdi_dates),
                "patch_events": len(cluster_dates(npdi_dates)),
            },
            "NP+DI+DQ": {
                "raw_dates": len(npdi_dq_dates),
                "patch_events": len(cluster_dates(npdi_dq_dates)),
            },
            "Hacker S+A": {
                "raw_dates": len(hacker_dates),
                "patch_events": len(cluster_dates(hacker_dates)),
            },
        },
        "summary": summary,
        "per_cve_absorption": per_cve,
    }

    # Print human-readable to stdout
    print()
    print("=" * 78)
    print("EPSS-MARGINAL-ON-TOP-OF-MODEL — 7-year manifest, 175 events")
    print("=" * 78)
    print()
    print(f"Model trigger counts (full manifest, 7-day clustered):")
    for m, d in output["model_trigger_counts"].items():
        print(f"  {m:14}: {d['raw_dates']:3} raw -> {d['patch_events']:3} patch events")
    print()
    for thr in THRESHOLDS:
        thr_key = f"epss_ge_{int(thr*100):02d}"
        s = summary[thr_key]
        print(f"EPSS >= {thr:.2f}: {s['standalone_raw_cves']} CVEs cross, "
              f"{s['standalone_patch_events']} patch events standalone")
        for model in models:
            m = s["marginal"][model]
            print(f"  marginal to {model:11}: "
                  f"{m['marginal_cves']:3} CVEs, "
                  f"{m['marginal_patch_events']:3} patch events  "
                  f"(absorbed {m['absorption_rate']})")
        print()

    sa = summary["hacker_sa_in_scope_8"]
    print(f"Hacker S+A row for the 8 in-scope exploited CVEs:")
    print(f"  day0 / day7 / day30 / eventually : "
          f"{sa['day_0']} / {sa['day_7']} / {sa['day_30']} / {sa['eventually']}")
    print(f"  patch events on manifest         : {sa['total_patch_events_on_manifest']}")
    print(f"  caught                           : {', '.join(sa['caught_cves'])}")
    print(f"  missed                           : {', '.join(sa['missed_cves'])}")
    print()

    tc = summary["timing_comparison"]
    print(f"Timing comparison (model = NP+DI+DQ, 30-day patch cycle):")
    print(f"  cohort: {tc['cohort_size']} CVEs; "
          f"{tc['avg_n_with_epss_coverage']} have EPSS real-time coverage; "
          f"pre-EPSS: {', '.join(tc['pre_epss_cves']) or 'none'}")
    print(f"  avg days faster vs EPSS >= 0.10  : {tc['avg_days_faster_vs_epss_10']} "
          f"(n={tc['avg_n_with_epss_coverage']})")
    print(f"  avg days faster vs EPSS >= 0.50  : {tc['avg_days_faster_vs_epss_50']} "
          f"(n={tc['avg_n_with_epss_coverage']})")
    cbe = tc["caught_before_exploit"]
    print(f"  caught before exploit (model)    : {cbe['model']}")
    print(f"  caught before exploit (EPSS>=.10): {cbe['epss_ge_10']}")
    print(f"  caught before exploit (EPSS>=.50): {cbe['epss_ge_50']}")
    print(f"  marginal model > EPSS >= 0.10    : {cbe['marginal_model_minus_epss_10']}")
    print(f"  marginal model > EPSS >= 0.50    : {cbe['marginal_model_minus_epss_50']}")
    print(f"  per-CVE detail:")
    for row in tc["per_cve"]:
        flags = []
        if row["is_pre_epss"]:
            flags.append("pre-EPSS")
        if row["model_caught_before_exploit"]:
            flags.append("model<exp")
        if row["epss_50_caught_before_exploit"]:
            flags.append("epss50<exp")
        print(f"    {row['cve']:18} ({row['name']:22}) "
              f"d10={row['delta_days_epss_10']:>5} d50={row['delta_days_epss_50']:>5} "
              f"t_exp={row['t_exploit']} ({row['t_exploit_source']}) "
              f"{','.join(flags)}")
    print()

    # ----------- Check / write -----------
    if args.check:
        if not DATASET_OUT.exists():
            print("FAIL — output file does not exist; run without --check to create.")
            return 1
        existing = json.load(open(DATASET_OUT))
        # Compare ignoring generated_at
        existing.pop("generated_at", None)
        proposed = dict(output)
        proposed.pop("generated_at", None)
        if json.dumps(existing, sort_keys=True) != json.dumps(proposed, sort_keys=True):
            print("FAIL — regeneration would change content.")
            return 1
        print("OK — content unchanged.")
        return 0

    DATASET_OUT.write_text(json.dumps(output, indent=2, sort_keys=True))
    print(f"Wrote {DATASET_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
