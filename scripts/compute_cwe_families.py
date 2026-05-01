#!/usr/bin/env python3
"""
Compute the cwe_data field that drives the cweChart on docs/dashboard.html.

Source: data/kev-snapshot-2026-05-01.json (full KEV catalog, 1,579 entries)

Per the prior AI's Q7 answer:
  - CWE-number → family lookup (memory_corruption, injection, auth, etc.)
  - Aggregated over the FULL KEV catalog (not the 2021+ window)
  - Counts by family in descending order

Family mapping (canonical, from the prior AI's answer):
  memory_corruption: 119, 120, 122, 125, 190, 416, 476, 787, 824
  injection:         77, 78, 79, 89, 94, 917
  auth:              287, 269, 306, 862, 863
  path_traversal:    22, 23, 36
  deserialization:   502
  info_disclosure:   200, 209
  ssrf:              918
  race:              362
  unknown:           entries with no CWE
  other:             everything else
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Family → set of CWE numbers. Order matters for ties; first match wins.
CWE_FAMILIES: list[tuple[str, set[int]]] = [
    ("memory_corruption", {119, 120, 122, 125, 190, 416, 476, 787, 824}),
    ("injection",         {77, 78, 79, 89, 94, 917}),
    ("auth",              {287, 269, 306, 862, 863}),
    ("path_traversal",    {22, 23, 36}),
    ("deserialization",   {502}),
    ("info_disclosure",   {200, 209}),
    ("ssrf",              {918}),
    ("race",              {362}),
]


def family_for(cwes: list[str]) -> str:
    """Return the family name for an entry's CWE list. First-match-wins."""
    if not cwes:
        return "unknown"
    nums = []
    for c in cwes:
        if isinstance(c, str) and c.startswith("CWE-"):
            try:
                nums.append(int(c.replace("CWE-", "")))
            except ValueError:
                pass
    if not nums:
        return "unknown"
    for fam, cwe_set in CWE_FAMILIES:
        if any(n in cwe_set for n in nums):
            return fam
    return "other"


def build() -> dict:
    snap_path = REPO / "data" / "kev-snapshot-2026-05-01.json"
    snap = json.load(open(snap_path))
    vulns = snap["vulnerabilities"]

    counter = Counter()
    for v in vulns:
        cwes = v.get("cwes", []) or []
        counter[family_for(cwes)] += 1

    # Build sorted output (descending by count, "other" last by convention)
    output_order = (["other"] +
                    [fam for fam, _ in CWE_FAMILIES] +
                    ["unknown"])
    cwe_data = []
    seen = set()
    # Sort by count desc, but the doc puts 'other' first historically — keep that
    sorted_fams = sorted(counter.items(), key=lambda x: (-x[1], x[0]))
    for fam, count in sorted_fams:
        cwe_data.append({"family": fam, "count": count})
        seen.add(fam)

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Canonical CWE-family aggregation backing the cweChart on "
            "docs/dashboard.html. Counts are over the full KEV catalog, "
            "not the 2021+ window."
        ),
        "methodology": {
            "source": str(snap_path.relative_to(REPO)),
            "scope": "full KEV catalog (all entries, all years)",
            "family_mapping": {fam: sorted(cwes) for fam, cwes in CWE_FAMILIES},
            "tie_breaking": "first family match wins (order in CWE_FAMILIES list)",
        },
        "summary": {
            "total_entries": len(vulns),
            "by_family": dict(counter.most_common()),
        },
        "cwe_data": cwe_data,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    args = ap.parse_args()

    out_path = REPO / "data" / "cwe-families.json"
    new = build()

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("cwe_data", "methodology", "description", "summary"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  total KEV entries: {new['summary']['total_entries']}")
    print(f"  by family:")
    for row in new["cwe_data"]:
        print(f"    {row['family']:20s} {row['count']:5d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
