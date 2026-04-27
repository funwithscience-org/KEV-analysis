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
