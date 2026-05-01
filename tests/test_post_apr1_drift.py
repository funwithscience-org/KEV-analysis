#!/usr/bin/env python3
"""
Verify the dashboard's POST_APR1 JS data block matches data/post-apr1-per-framework.json.

The Live Tracker chart embeds a copy of the JSON inside docs/dashboard.html
so the page is statically renderable. This test catches the case where the
JSON is regenerated but the embed isn't repatched (or vice versa) — the
dashboard would then show stale data without anyone noticing.

Run: python3 tests/test_post_apr1_drift.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "data" / "post-apr1-per-framework.json"
HTML = REPO / "docs" / "dashboard.html"


def _arr(name: str, src: str) -> list[int]:
    m = re.search(rf"{name}:\s*\[([^\]]+)\]", src)
    if not m:
        raise AssertionError(f"could not find {name} array in dashboard.html POST_APR1")
    return [int(x.strip()) for x in m.group(1).split(",") if x.strip()]


def _str(name: str, src: str) -> str:
    m = re.search(rf'{name}:\s*"([^"]*)"', src)
    if not m:
        raise AssertionError(f"could not find {name} string in dashboard.html POST_APR1")
    return m.group(1)


def main() -> int:
    if not DATA.exists():
        print(f"FAIL: {DATA} missing — run scripts/refresh_post_apr1.py")
        return 1
    if not HTML.exists():
        print(f"FAIL: {HTML} missing")
        return 1

    data = json.loads(DATA.read_text())
    src = HTML.read_text()

    # Locate just the POST_APR1 block to scope our regexes
    m = re.search(r"const POST_APR1 = \{(.*?)^\};", src, flags=re.DOTALL | re.MULTILINE)
    if not m:
        print("FAIL: could not locate `const POST_APR1 = { ... };` in dashboard.html")
        return 1
    post_apr1 = m.group(1)

    fails = 0

    expected_through = data["snapshot_through"]
    actual_through = _str("snapshot_through", post_apr1)
    if expected_through != actual_through:
        print(f"FAIL: snapshot_through drift — JSON {expected_through} vs HTML {actual_through}")
        fails += 1

    for name, json_key in [
        ("all_ch_clusters",   "all_ch_clusters"),
        ("model_clusters",    "model_union_clusters"),
        ("exploited",         "exploited_counts"),
    ]:
        expected = data["summary"][json_key]
        actual = _arr(name, post_apr1)
        if expected != actual:
            print(f"FAIL: {name} drift — JSON {expected} vs HTML {actual}")
            fails += 1

    # labels (string array)
    label_match = re.search(r'labels:\s*\[([^\]]+)\]', post_apr1)
    if label_match:
        labels_html = [s.strip().strip('"') for s in label_match.group(1).split(",")]
        labels_json = data["summary"]["labels"]
        if labels_html != labels_json:
            print(f"FAIL: labels drift — JSON {labels_json} vs HTML {labels_html}")
            fails += 1

    # Per-event row count sanity (HTML embed should hold every event the JSON
    # has across the 5 frameworks)
    event_rows = re.findall(r"^\s*\{date:\"\d{4}-\d{2}-\d{2}\"", post_apr1, flags=re.MULTILINE)
    expected_events = sum(len(data["frameworks"][k]["events"])
                           for k in ("spring", "nodejs", "django", "netty", "real_java"))
    if len(event_rows) != expected_events:
        print(f"FAIL: per-event row count drift — JSON {expected_events} events vs HTML {len(event_rows)}")
        fails += 1

    if fails == 0:
        print(f"[post-apr1-drift] OK — POST_APR1 embed matches JSON ({expected_events} rows, "
              f"snapshot {expected_through})")
        return 0
    print(f"[post-apr1-drift] {fails} drift(s) detected — re-run scripts/refresh_post_apr1.py")
    return 1


if __name__ == "__main__":
    sys.exit(main())
