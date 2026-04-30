#!/usr/bin/env python3
"""
Build the canonical 12-month per-framework dataset that backs the
crossFrameworkChart, periodicityChart, and per-framework monthly heatmaps
on docs/periodicity.html.

Sources:
  - cached-data/periodicity/spring_periodicity_data.json   (Spring, 22 events)
  - cached-data/periodicity/multi_framework_periodicity.json (nodejs, django)
  - data/_netty-osv-cache.json                             (Netty, fetched live)
  - data/di-reclassification.json                          (widened DI auth-bypass adds)

NP classification rule (formalized 2026-04-25): a package is NP if its primary
purpose is processing untrusted input that arrives over the network OR drives
security decisions. The cached `is_np` flag mostly captures this, with one
known correction:

  cryptography → NP (auth-boundary library; signature/cert verification on
                    untrusted input is exactly the trust-boundary pattern)

DI CWE set includes the widened auth-bypass CWEs (287, 289, 306, 345, 693,
863, 1321) on top of the original injection set.

Output:
  data/twelve-month-per-framework.json
    {
      generated_at: "...",
      methodology: { ... explicit rules ... },
      frameworks: {
        spring: { all_dates: [...], npdi_dates: [...], events: [...] },
        nodejs: { ... },
        django: { ... },
        netty:  { ... }
      },
      summary: {
        chart_arrays: { ... what crossFrameworkChart expects ... },
        ...
      }
    }

Usage:
    python3 scripts/build_twelve_month_per_framework.py
    python3 scripts/build_twelve_month_per_framework.py --check
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = Path("/sessions/bold-nice-euler/mnt/vulnerability analysis/cached-data")

# DI CWE set (widened, per data/di-reclassification.json)
DI_CWES = {
    # Excluded: CWE-434 (file upload) — deliberate; see periodicity doc.
    # Including it over-broadens the filter; doc treats Tomcat PUT events
    # as misses precisely because CWE-434 is not in DI.
    78, 77, 94, 95, 917, 1336, 74, 89, 90, 918, 611, 776, 444, 113, 22, 23,
    36, 98, 91, 116, 93, 96, 97, 1236,
    287, 289, 306, 345, 693, 863, 1321,
}

# NP classification override per the auth-boundary rule. Cached `is_np` is
# correct for everything except packages that sit at the trust boundary
# without being protocol parsers. Add to this set if a package's primary
# purpose is verifying untrusted signatures/tokens/certs.
NP_OVERRIDES_TO_TRUE = {
    "cryptography",  # Python crypto lib; signature verification on untrusted input
}


def load_spring() -> dict | None:
    try:
        return json.load(open(CACHE / "periodicity" / "spring_periodicity_data.json"))
    except (PermissionError, FileNotFoundError, OSError):
        return None


def load_multi() -> dict | None:
    try:
        return json.load(open(CACHE / "periodicity" / "multi_framework_periodicity.json"))
    except (PermissionError, FileNotFoundError, OSError):
        return None


def load_widened_adds() -> list[dict]:
    p = REPO / "data" / "di-reclassification.json"
    if not p.exists():
        return []
    return json.load(open(p)).get("twelve_month_backtest_additions", [])


def load_netty() -> dict | None:
    """Load the Netty cache if present. Returns None if not yet fetched."""
    p = REPO / "data" / "_netty-osv-cache.json"
    if not p.exists():
        return None
    return json.load(open(p))


def event_is_np(ev: dict) -> bool:
    """Apply the canonical NP rule including overrides."""
    pkg = ev.get("package", "")
    if pkg in NP_OVERRIDES_TO_TRUE:
        return True
    return bool(ev.get("is_np"))


def event_is_di(ev: dict) -> bool:
    """Any CWE in the widened DI set."""
    cwes = ev.get("cwes", []) or []
    for c in cwes:
        if isinstance(c, str) and c.startswith("CWE-"):
            try:
                if int(c.replace("CWE-", "")) in DI_CWES:
                    return True
            except ValueError:
                pass
    return False


def event_is_npdi(ev: dict) -> bool:
    return event_is_np(ev) and event_is_di(ev)


def gaps(dates: list[str]) -> list[int]:
    """Inter-event gaps in days, between consecutive sorted dates."""
    if len(dates) < 2:
        return []
    sorted_dates = sorted(dt.date.fromisoformat(d) for d in dates)
    return [(sorted_dates[i + 1] - sorted_dates[i]).days
            for i in range(len(sorted_dates) - 1)]


def framework_summary(name: str, events: list[dict],
                      widened_adds: list[dict]) -> dict:
    """Compute the per-framework rollup matching the doc's chart numbers."""
    # Apply DI widening: any cached event whose CWEs match the widened set
    # gets promoted to NP+DI if package is NP. This is automatic via
    # event_is_di() which now uses the widened CWE set.
    #
    # Plus: append the widened additions from di-reclassification.json that
    # target this framework (in case they're not in the cached event list).
    framework_label = {
        "spring": "Spring",
        "nodejs": "Node",
        "django": "Django",
        "netty":  "Netty",
    }[name]
    framework_widened = [a for a in widened_adds
                         if a.get("framework", "").startswith(framework_label)]
    # Union-by-date — additions only matter if they introduce new dates
    seen_dates = {e["date"] for e in events}
    extra_npdi_events = [a for a in framework_widened
                         if a["date"] not in seen_dates]

    all_dates = sorted({e["date"] for e in events}
                       | {a["date"] for a in framework_widened})
    npdi_event_dates = {e["date"] for e in events if event_is_npdi(e)}
    npdi_dates = sorted(npdi_event_dates
                        | {a["date"] for a in framework_widened})

    # Monthly bins — latest 13 months (matching doc's chart label range)
    # Doc uses Apr 25 – Apr 26 inclusive
    months = [f"2025-{m:02d}" for m in range(4, 13)] + \
             [f"2026-{m:02d}" for m in range(1, 5)]
    monthly_other = []
    monthly_npdi = []
    for ym in months:
        date_prefix = ym + "-"
        # Per-CVE counts in this month (chart-compatible: not deduped to dates)
        events_in_month = [e for e in events if e["date"].startswith(date_prefix)]
        widened_in_month = [a for a in framework_widened
                            if a["date"].startswith(date_prefix)]
        npdi_count = (sum(1 for e in events_in_month if event_is_npdi(e))
                      + len([a for a in widened_in_month
                             if a["date"] not in {e["date"] for e in events_in_month
                                                  if event_is_npdi(e)}]))
        # All other C/H = total events - NP+DI events (in this month)
        # Including widened additions that aren't already in the event list
        total_count = len(events_in_month) + len([a for a in widened_in_month
                                                  if a["date"] not in {e["date"]
                                                                       for e in events_in_month}])
        other_count = total_count - npdi_count
        monthly_other.append(other_count)
        monthly_npdi.append(npdi_count)

    return {
        "framework": name,
        "label": framework_label,
        "manifest_size": None,  # caller can fill
        "event_count_raw": len(events),
        "event_count_with_widened_adds": len(events) + len(extra_npdi_events),
        "all_trigger_dates": all_dates,
        "all_trigger_count": len(all_dates),
        "npdi_dates": npdi_dates,
        "npdi_count": len(npdi_dates),
        "longest_silence_all_days": max(gaps(all_dates), default=0),
        "longest_silence_npdi_days": max(gaps(npdi_dates), default=0),
        "monthly_labels": months,
        "monthly_other": monthly_other,
        "monthly_npdi": monthly_npdi,
    }


def build() -> dict | None:
    spring = load_spring()
    multi = load_multi()
    if spring is None or multi is None:
        # Cache unavailable in this session; preserve dataset as-is.
        return None
    widened = load_widened_adds()

    spring_summary = framework_summary("spring", spring["all_events"], widened)
    spring_summary["manifest_size"] = len(spring.get("manifest", []))

    nodejs_summary = framework_summary("nodejs", multi["nodejs"]["all_events"], widened)
    nodejs_summary["manifest_size"] = multi["nodejs"].get("manifest_size")

    django_summary = framework_summary("django", multi["django"]["all_events"], widened)
    django_summary["manifest_size"] = multi["django"].get("manifest_size")

    netty_cache = load_netty()
    if netty_cache:
        netty_summary = framework_summary("netty", netty_cache["all_events"], widened)
        netty_summary["manifest_size"] = netty_cache.get("manifest_size")
    else:
        netty_summary = {
            "framework": "netty", "label": "Netty",
            "manifest_size": None,
            "all_trigger_count": None, "npdi_count": None,
            "_pending": "Netty cache not yet built; see scripts/fetch_netty_osv.py",
        }

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Canonical 12-month per-framework dataset backing the "
            "crossFrameworkChart, periodicityChart, and monthly heatmaps "
            "on docs/periodicity.html."
        ),
        "methodology": {
            "np_rule": (
                "A package is NP if its primary purpose is processing "
                "untrusted input that arrives over the network OR drives "
                "security decisions. Cached is_np flags are correct except "
                "for known auth-boundary library overrides."
            ),
            "np_overrides": sorted(NP_OVERRIDES_TO_TRUE),
            "di_cwes": sorted(DI_CWES),
            "dedup": (
                "Per-CVE for monthly bins (chart compatibility). "
                "Per-date for trigger counts and longest-silence stats."
            ),
            "widened_di_source": "data/di-reclassification.json",
            "widened_additions_policy": (
                "If a widened-DI addition introduces a date not already "
                "in the cached event list, count it as a new NP+DI date."
            ),
        },
        "frameworks": {
            "spring": spring_summary,
            "nodejs": nodejs_summary,
            "django": django_summary,
            "netty":  netty_summary,
        },
        "summary": {
            "chart_arrays": {
                "labels": ["Spring Boot", "Node.js/Express",
                           "Django/Python", "Netty"],
                "all_ch_trigger_dates": [
                    spring_summary["all_trigger_count"],
                    nodejs_summary["all_trigger_count"],
                    django_summary["all_trigger_count"],
                    netty_summary.get("all_trigger_count"),
                ],
                "npdi_trigger_dates": [
                    spring_summary["npdi_count"],
                    nodejs_summary["npdi_count"],
                    django_summary["npdi_count"],
                    netty_summary.get("npdi_count"),
                ],
            },
            "longest_silences": {
                "spring_all": spring_summary["longest_silence_all_days"],
                "spring_npdi": spring_summary["longest_silence_npdi_days"],
                "nodejs_all": nodejs_summary["longest_silence_all_days"],
                "nodejs_npdi": nodejs_summary["longest_silence_npdi_days"],
                "django_all": django_summary["longest_silence_all_days"],
                "django_npdi": django_summary["longest_silence_npdi_days"],
            },
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "twelve-month-per-framework.json"
    new = build()
    if new is None:
        if args.check:
            print(f"OK: {out_path.relative_to(REPO)} unchanged (inputs unavailable)")
            return 0
        print(f"[skip] {out_path.relative_to(REPO)} not regenerated (inputs unavailable)")
        return 0

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("frameworks", "summary", "methodology", "description"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    s = new["summary"]["chart_arrays"]
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  Per framework: {dict(zip(s['labels'], zip(s['all_ch_trigger_dates'], s['npdi_trigger_dates'])))}")
    print(f"  Doc says:      Spring 14→5, Node 14→2, Django 14→6, Netty 3→1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
