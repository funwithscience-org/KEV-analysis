#!/usr/bin/env python3
"""
Numeric invariants on the DATA blobs in docs/dashboard.html and docs/index.html.

The DATA blob is the single source of truth that drives every chart and every
hardcoded-looking number on the page. This suite enforces:

  1.  Sums of layer_data.kev match the classifications JSON windowed total.
  2.  ransomware_count matches sum(ransomware_data) matches classifications JSON
      windowed-ransomware count.
  3.  Each layer's kev count matches the classifications JSON layer count.
  4.  Every per-layer rate equals round(kev / nvd * 100, 2).
  5.  No per-layer rate exceeds 100%.
  6.  All 15 canonical layers are present.
  7.  layer_data and ransomware_data are identical across dashboard and walkthrough.

When to add tests here:
  * Any time a new DATA field is added (e.g. new chart, new per-layer stat).
  * Any time a new page gets a DATA blob — add it to DATA_BLOB_SOURCES in _common.py.

If tests here fail:
  * Usually the two HTML pages drifted (someone edited one and forgot the other).
  * Or a rate was hand-typed and doesn't match kev/nvd arithmetic.
  * Or the classifier was re-run but only one DATA blob was regenerated.
  * Fix the drift. Don't relax the check.
"""

from __future__ import annotations

import json
import sys
from collections import Counter

from _common import REPO  # noqa: F401  (used in cwe/top_products checks below)
from _common import (
    LAYERS,
    TestReporter,
    all_data_blobs,
    load_classifications,
    windowed,
)


def main() -> int:
    r = TestReporter("data-invariants")

    classif = load_classifications()
    win = windowed(classif["classifications"])
    ransom_win = [x for x in win if x["isRansomware"]]

    expected_windowed = len(win)
    expected_ransom = len(ransom_win)
    expected_layer_counts = Counter(x["layer"] for x in win)

    blobs = all_data_blobs()

    # Collect per-page layer_data / ransomware_data for cross-page equality below
    per_page_layer = {}
    per_page_ransom = {}

    for path, data in blobs:
        tag = path.name

        # --- 1. sum(layer_data.kev) == windowed total ---
        total = sum(x["kev"] for x in data["layer_data"])
        r.check(
            total == expected_windowed,
            f"{tag}: sum(layer_data.kev)={total}, expected {expected_windowed} "
            f"(from classifications JSON)",
        )

        # --- 2. ransomware_count == sum(ransomware_data) == windowed ransomware ---
        r.check(
            data["ransomware_count"] == expected_ransom,
            f"{tag}: ransomware_count={data['ransomware_count']}, expected {expected_ransom}",
        )
        rsum = sum(x["count"] for x in data["ransomware_data"])
        r.check(
            rsum == data["ransomware_count"],
            f"{tag}: sum(ransomware_data)={rsum} != ransomware_count={data['ransomware_count']}",
        )

        # --- 3. Per-layer kev matches classifications ---
        for row in data["layer_data"]:
            exp = expected_layer_counts.get(row["layer"], 0)
            r.check(
                row["kev"] == exp,
                f"{tag}: layer={row['layer']} kev={row['kev']}, expected {exp} from classifier",
            )

        # --- 4. rate == round(kev/nvd*100, 2) ---
        # Tight: stored rate must round to the same 2dp value as computed.
        # 0.01 tolerance is too loose — float subtraction makes 78.18 vs 78.19
        # come out as 0.009999… and slips through.
        for row in data["layer_data"]:
            if row["nvd"] == 0:
                continue
            expected_rate = round(row["kev"] / row["nvd"] * 100, 2)
            r.check(
                round(row["rate"], 2) == expected_rate,
                f"{tag}: layer={row['layer']} rate={row['rate']} != "
                f"{expected_rate} (= {row['kev']}/{row['nvd']}*100)",
            )

        # --- 5. no rate > 100 ---
        for row in data["layer_data"]:
            r.check(
                row["rate"] <= 100.0 + 1e-9,
                f"{tag}: layer={row['layer']} rate={row['rate']}% exceeds 100% "
                f"(kev={row['kev']}, nvd={row['nvd']}) — denominator is stale "
                f"or classifier is overcounting",
            )

        # --- 6. all 15 layers present ---
        seen = {row["layer"] for row in data["layer_data"]}
        missing = LAYERS - seen
        extra = seen - LAYERS
        r.check(not missing, f"{tag}: layer_data missing layers: {sorted(missing)}")
        r.check(not extra, f"{tag}: layer_data has unexpected layers: {sorted(extra)}")

        # --- 7. total_kev field consumed by KPI auto-fill in prose ---
        r.check(
            "total_kev" in data,
            f"{tag}: DATA.total_kev missing — needed for prose KPI auto-fill",
        )
        if "total_kev" in data:
            kev_total = data["total_kev"]
            r.check(
                isinstance(kev_total, int) and kev_total > 0,
                f"{tag}: DATA.total_kev={kev_total!r} not a positive int",
            )
            r.check(
                kev_total >= total,
                f"{tag}: DATA.total_kev={kev_total} < windowed sum {total} "
                f"(catalog total can't be smaller than its 2021+ subset)",
            )
            # Cross-check against classifications JSON
            r.check(
                kev_total == len(classif["classifications"]),
                f"{tag}: DATA.total_kev={kev_total} != classifications JSON entry "
                f"count {len(classif['classifications'])} — refresh agent or "
                f"classifier rebuild left them out of sync",
            )

        # --- 8. total_nvd, if present, must match sum(layer_data.nvd) ---
        if "total_nvd" in data:
            nvd_sum = sum(x["nvd"] for x in data["layer_data"])
            r.check(
                data["total_nvd"] == nvd_sum,
                f"{tag}: DATA.total_nvd={data['total_nvd']} != "
                f"sum(layer_data.nvd)={nvd_sum}",
            )

        # --- 8b. cwe_data must match data/cwe-families.json output ---
        cwe_path = REPO / "data" / "cwe-families.json"
        if cwe_path.exists() and "cwe_data" in data:
            generator_cwe = json.load(open(cwe_path))["cwe_data"]
            r.check(
                data["cwe_data"] == generator_cwe,
                f"{tag}: DATA.cwe_data drifted from data/cwe-families.json. "
                f"Run scripts/compute_cwe_families.py and update DATA blob.",
            )

        # --- 8c. top_products must match data/top-products.json output ---
        tp_path = REPO / "data" / "top-products.json"
        if tp_path.exists() and "top_products" in data:
            generator_tp = json.load(open(tp_path))["top_products"]
            r.check(
                data["top_products"] == generator_tp,
                f"{tag}: DATA.top_products drifted from data/top-products.json. "
                f"Run scripts/compute_top_products.py and update DATA blob.",
            )

        # --- 8d. tte_data structural invariants (no generator yet) ---
        if "tte_data" in data:
            tte = data["tte_data"]
            r.check(
                isinstance(tte, list) and len(tte) >= 1,
                f"{tag}: tte_data must be a non-empty list",
            )
            for row in tte:
                for field in ("year", "n", "median", "p25", "p75", "mean"):
                    r.check(
                        field in row,
                        f"{tag}: tte_data row missing field {field!r}: {row}",
                    )
                if "p25" in row and "median" in row and "p75" in row:
                    r.check(
                        row["p25"] <= row["median"] <= row["p75"],
                        f"{tag}: tte_data row {row.get('year')} percentiles "
                        f"out of order: p25={row['p25']} median={row['median']} "
                        f"p75={row['p75']}",
                    )
            # Years should be ascending
            years = [r2["year"] for r2 in tte if "year" in r2]
            r.check(
                years == sorted(years),
                f"{tag}: tte_data years not in ascending order: {years}",
            )

        # --- 9. prep for cross-page equality ---
        per_page_layer[tag] = {row["layer"]: (row["kev"], row["nvd"], row["rate"])
                               for row in data["layer_data"]}
        per_page_ransom[tag] = {row["layer"]: row["count"]
                                for row in data["ransomware_data"]}

    # --- 7. dashboard and index must agree on layer_data and ransomware_data ---
    if len(per_page_layer) >= 2:
        keys = list(per_page_layer)
        ref = keys[0]
        for other in keys[1:]:
            r.check(
                per_page_layer[ref] == per_page_layer[other],
                f"layer_data differs between {ref} and {other}",
            )
            r.check(
                per_page_ransom[ref] == per_page_ransom[other],
                f"ransomware_data differs between {ref} and {other}",
            )

    return r.summary_exit_code()


if __name__ == "__main__":
    sys.exit(main())
