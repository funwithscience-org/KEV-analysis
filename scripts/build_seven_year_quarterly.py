#!/usr/bin/env python3
"""
Build the canonical 7-year quarterly aggregation that backs the
realManifestChart on docs/periodicity.html (rmOther + rmNPDI arrays).

Source: data/seven-year-manifest-events.json (built by
scripts/build_seven_year_npdi.py).

Per the prior AI's Q3 answer:
  - Calendar quarters (Q1 = Jan/Feb/Mar)
  - Per-CVE counts (raw, not deduped to dates)
  - NP+DI is a strict subset of total C/H
  - rmOther = total C/H - NP+DI per quarter

Quarter range: 2018Q4 through 2026Q2 (31 quarters), matching the doc's
hardcoded rmLabels.

Output: data/seven-year-quarterly.json
    {
      methodology: { ... },
      labels: ["18Q4", ..., "26Q2"],
      total_ch: [counts per quarter],
      npdi: [counts per quarter],
      other: [counts per quarter],         # = total_ch - npdi
      summary: { sum_total_ch, sum_npdi, sum_other }
    }
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

QUARTERS = [
    "18Q4",
    "19Q1", "19Q2", "19Q3", "19Q4",
    "20Q1", "20Q2", "20Q3", "20Q4",
    "21Q1", "21Q2", "21Q3", "21Q4",
    "22Q1", "22Q2", "22Q3", "22Q4",
    "23Q1", "23Q2", "23Q3", "23Q4",
    "24Q1", "24Q2", "24Q3", "24Q4",
    "25Q1", "25Q2", "25Q3", "25Q4",
    "26Q1", "26Q2",
]


def date_to_quarter(date_str: str) -> str | None:
    """Return YYQn for a YYYY-MM-DD date, or None if outside the window."""
    try:
        d = dt.date.fromisoformat(date_str)
    except (ValueError, TypeError):
        return None
    yy = d.year % 100
    q = (d.month - 1) // 3 + 1
    label = f"{yy:02d}Q{q}"
    return label if label in QUARTERS else None


def build() -> dict:
    src = REPO / "data" / "seven-year-manifest-events.json"
    if not src.exists():
        raise FileNotFoundError(f"Run scripts/build_seven_year_npdi.py first: {src}")
    ds = json.load(open(src))

    total_per_q: dict[str, int] = defaultdict(int)
    npdi_per_q: dict[str, int] = defaultdict(int)

    for ev in ds.get("events", []):
        q = date_to_quarter(ev.get("published"))
        if q is None:
            continue
        total_per_q[q] += 1
        if ev.get("is_np") and ev.get("is_di"):
            npdi_per_q[q] += 1

    total_ch = [total_per_q.get(q, 0) for q in QUARTERS]
    npdi = [npdi_per_q.get(q, 0) for q in QUARTERS]
    other = [t - n for t, n in zip(total_ch, npdi)]

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Canonical 7-year quarterly aggregation backing the "
            "realManifestChart (rmOther + rmNPDI arrays) on "
            "docs/periodicity.html."
        ),
        "methodology": {
            "source_dataset": "data/seven-year-manifest-events.json",
            "bucket_logic": (
                "Calendar quarters (Q1=Jan/Feb/Mar). Per-CVE count "
                "(NOT deduped to dates) per the prior AI's Q3 answer."
            ),
            "stacking": "rmOther + rmNPDI = total C/H per quarter",
            "manifest_scope_note": (
                "The seven-year-manifest-events.json was built from the "
                "expanded 54-package manifest (script's 48 + 6 editorial). "
                "If the doc's manifest scope is later trimmed, regenerate "
                "the source dataset and rerun this aggregator."
            ),
        },
        "labels": QUARTERS,
        "total_ch": total_ch,
        "npdi": npdi,
        "other": other,
        "summary": {
            "quarters": len(QUARTERS),
            "sum_total_ch": sum(total_ch),
            "sum_npdi": sum(npdi),
            "sum_other": sum(other),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "seven-year-quarterly.json"
    new = build()

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("labels", "total_ch", "npdi", "other", "methodology", "description"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    s = new["summary"]
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  quarters: {s['quarters']}")
    print(f"  sum total C/H: {s['sum_total_ch']}")
    print(f"  sum NP+DI:     {s['sum_npdi']}")
    print(f"  sum other:     {s['sum_other']}")
    print()
    print("  Doc hardcoded arrays (for comparison):")
    print(f"    rmOther sum: 130")
    print(f"    rmNPDI sum:  30")
    return 0


if __name__ == "__main__":
    sys.exit(main())
