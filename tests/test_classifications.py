#!/usr/bin/env python3
"""
Integrity checks on data/kev-layer-classifications.json.

The classifications file is the output of data/kev-classifier.py and the
input to every numeric claim on the site. If it's malformed or drifts from
the pinned snapshot, everything downstream silently degrades.

Checks:
  1.  Top-level keys present: classifications, summary, source, input_sha256_16,
      kev_catalog_version, generated_at.
  2.  Entry count matches the pinned snapshot's `vulnerabilities` length.
  3.  Every classification has: cveID, year, layer, isRansomware, vendor, product.
  4.  Every layer is in the 15-layer canonical set.
  5.  Every year matches int(cveID.split('-')[1]).
  6.  isRansomware is a bool.
  7.  summary.windowed_kev equals count of entries with year >= 2021.
  8.  summary.ransomware_windowed equals windowed && isRansomware.
  9.  summary.ransomware_total equals all isRansomware regardless of year.
 10.  summary.layer_counts_windowed matches recomputed counts.

If tests here fail:
  * The JSON was hand-edited (don't). Regenerate from the classifier.
  * The snapshot and the classifications drifted. Re-run:
      python3 data/kev-classifier.py --input data/kev-snapshot-YYYY-MM-DD.json --no-snapshot
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from _common import LAYERS, REPO, TestReporter, load_classifications


def main() -> int:
    r = TestReporter("classifications")

    classif = load_classifications()

    # --- 1. top-level shape ---
    for key in ("classifications", "summary", "source",
                "input_sha256_16", "kev_catalog_version", "generated_at"):
        r.check(key in classif, f"classifications JSON missing top-level key: {key}")

    entries = classif.get("classifications", [])
    summary = classif.get("summary", {})

    # --- 2. entry count matches pinned snapshot ---
    snap_version = classif.get("kev_catalog_version")
    if snap_version:
        # Pick up any kev-snapshot-*.json in data/. If zero or >1 we still run
        # other checks but skip this one.
        snaps = sorted((REPO / "data").glob("kev-snapshot-*.json"))
        if len(snaps) == 1:
            with open(snaps[0]) as f:
                snap = json.load(f)
            r.check(
                len(snap["vulnerabilities"]) == len(entries),
                f"classifications count ({len(entries)}) != snapshot count "
                f"({len(snap['vulnerabilities'])}) for {snaps[0].name}",
            )
            r.check(
                snap.get("catalogVersion") == snap_version,
                f"classifications catalog_version={snap_version} != "
                f"snapshot catalogVersion={snap.get('catalogVersion')}",
            )
        elif len(snaps) > 1:
            print(f"[info] multiple snapshots present, skipping snapshot count check: "
                  f"{[p.name for p in snaps]}")

    # --- 3,4,5,6. per-entry field + type checks ---
    required_fields = ("cveID", "year", "layer", "isRansomware", "vendor", "product")
    for e in entries:
        missing = [k for k in required_fields if k not in e]
        if missing:
            r.check(False, f"entry {e.get('cveID', '?')} missing fields: {missing}")
            continue

        # layer in canonical set
        r.check(
            e["layer"] in LAYERS,
            f"{e['cveID']}: layer {e['layer']!r} not in canonical 15-layer set",
        )

        # year matches cveID
        try:
            expected_year = int(e["cveID"].split("-")[1])
            r.check(
                e["year"] == expected_year,
                f"{e['cveID']}: year={e['year']} != cveID-derived year {expected_year}",
            )
        except (IndexError, ValueError):
            r.check(False, f"{e['cveID']}: cveID shape is unusable")

        # isRansomware must be a real bool
        r.check(
            isinstance(e["isRansomware"], bool),
            f"{e['cveID']}: isRansomware is {type(e['isRansomware']).__name__}, "
            f"expected bool",
        )

    # --- 7,8,9. summary counts match recomputed ---
    windowed = [e for e in entries if e.get("year") and e["year"] >= 2021]
    recomputed_windowed = len(windowed)
    recomputed_ransom_win = sum(1 for e in windowed if e.get("isRansomware"))
    recomputed_ransom_all = sum(1 for e in entries if e.get("isRansomware"))

    r.check(
        summary.get("windowed_kev") == recomputed_windowed,
        f"summary.windowed_kev={summary.get('windowed_kev')} != recomputed {recomputed_windowed}",
    )
    r.check(
        summary.get("ransomware_windowed") == recomputed_ransom_win,
        f"summary.ransomware_windowed={summary.get('ransomware_windowed')} != "
        f"recomputed {recomputed_ransom_win}",
    )
    r.check(
        summary.get("ransomware_total") == recomputed_ransom_all,
        f"summary.ransomware_total={summary.get('ransomware_total')} != "
        f"recomputed {recomputed_ransom_all}",
    )
    r.check(
        summary.get("total_kev") == len(entries),
        f"summary.total_kev={summary.get('total_kev')} != len(classifications)={len(entries)}",
    )

    # --- 10. per-layer windowed counts match ---
    recomputed_layers = dict(Counter(e["layer"] for e in windowed))
    stored_layers = summary.get("layer_counts_windowed", {})
    # Compare both directions to catch missing/extra keys
    for layer, n in recomputed_layers.items():
        r.check(
            stored_layers.get(layer) == n,
            f"summary.layer_counts_windowed[{layer}]={stored_layers.get(layer)} "
            f"!= recomputed {n}",
        )
    for layer, n in stored_layers.items():
        if layer not in recomputed_layers:
            r.check(
                False,
                f"summary.layer_counts_windowed[{layer}]={n} but recomputed count is 0",
            )

    return r.summary_exit_code()


if __name__ == "__main__":
    sys.exit(main())
