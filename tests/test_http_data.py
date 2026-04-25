#!/usr/bin/env python3
"""
Numeric invariants on the http_data table.

http_data drives the central thesis chart: "network-parsing CVEs are exploited
at 3-6x the rate of non-parsing CVEs at the same CVSS severity." The lift
numbers have to be arithmetically honest or the whole argument collapses.

Per-bucket checks:
  1.  http_kev <= http_total (can't exploit more than exist)
  2.  nonhttp_kev <= nonhttp_total
  3.  http_rate == round(http_kev / http_total * 100, 2)
  4.  nonhttp_rate == round(nonhttp_kev / nonhttp_total * 100, 2)
  5.  lift ≈ http_rate / nonhttp_rate  (within 1dp rounding tolerance)

Also:
  6.  http_data is identical across dashboard and walkthrough.

When to add tests here:
  * Any time a new http_data bucket is added (e.g. CVSS <6 range).
  * Any time a new column is added to the lift table.

If tests here fail:
  * Someone hand-typed a rate and the rate no longer matches the counts.
  * The lift number was adjusted without recomputing it.
  * The two HTML pages drifted.
"""

from __future__ import annotations

import sys

from _common import TestReporter, all_data_blobs


# Tolerance for the lift check. Rates are stored to 2dp, lift to 1dp; the
# rounding amplification can drift up to ~0.3 for small denominators. Anything
# beyond that indicates a real disagreement.
LIFT_TOLERANCE = 0.35


def main() -> int:
    r = TestReporter("http-data")

    blobs = all_data_blobs()
    per_page = {}

    for path, data in blobs:
        tag = path.name
        http_data = data.get("http_data")
        r.check(http_data is not None, f"{tag}: http_data missing")
        if http_data is None:
            continue

        for row in http_data:
            ctx = f"{tag} bucket={row['bucket']}"

            # --- 1,2. counts bounded by totals ---
            r.check(
                row["http_kev"] <= row["http_total"],
                f"{ctx}: http_kev={row['http_kev']} > http_total={row['http_total']}",
            )
            r.check(
                row["nonhttp_kev"] <= row["nonhttp_total"],
                f"{ctx}: nonhttp_kev={row['nonhttp_kev']} > nonhttp_total={row['nonhttp_total']}",
            )

            # --- 3,4. rate arithmetic (tight: same 2dp value, no float slop) ---
            if row["http_total"] > 0:
                expected = round(row["http_kev"] / row["http_total"] * 100, 2)
                r.check(
                    round(row["http_rate"], 2) == expected,
                    f"{ctx}: http_rate={row['http_rate']} != {expected} "
                    f"(= {row['http_kev']}/{row['http_total']}*100)",
                )
            if row["nonhttp_total"] > 0:
                expected = round(row["nonhttp_kev"] / row["nonhttp_total"] * 100, 2)
                r.check(
                    round(row["nonhttp_rate"], 2) == expected,
                    f"{ctx}: nonhttp_rate={row['nonhttp_rate']} != {expected} "
                    f"(= {row['nonhttp_kev']}/{row['nonhttp_total']}*100)",
                )

            # --- 5. lift ≈ http_rate / nonhttp_rate ---
            if row["nonhttp_rate"] > 0:
                expected_lift = row["http_rate"] / row["nonhttp_rate"]
                r.check(
                    abs(row["lift"] - expected_lift) <= LIFT_TOLERANCE,
                    f"{ctx}: lift={row['lift']} vs computed "
                    f"{row['http_rate']}/{row['nonhttp_rate']}={expected_lift:.3f} "
                    f"(tolerance ±{LIFT_TOLERANCE})",
                )

        per_page[tag] = http_data

    # --- 6. cross-page identity ---
    if len(per_page) >= 2:
        keys = list(per_page)
        ref = keys[0]
        for other in keys[1:]:
            r.check(
                per_page[ref] == per_page[other],
                f"http_data differs between {ref} and {other}",
            )

    return r.summary_exit_code()


if __name__ == "__main__":
    sys.exit(main())
