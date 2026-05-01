#!/usr/bin/env python3
"""Embed data/model-run-log.json into docs/glasswing.html.

GitHub Pages serves from /docs only, so we can't fetch /data/* from the
page at runtime. Instead, the canonical model-run log lives at
data/model-run-log.json (auditable, repo-tracked) and gets inlined into
docs/glasswing.html each time it changes.

The placeholder in glasswing.html looks like:
  /*BEGIN_MODEL_RUN_LOG*/<...anything...>/*END_MODEL_RUN_LOG*/
This script replaces whatever is between the markers with the current
JSON payload (compact, no indent).

Run it:
  - manually after editing data/model-run-log.json
  - automatically as the last step of the daily refresh agent

If the placeholder markers aren't found, it errors loudly.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOG = REPO / "data" / "model-run-log.json"
CONFIG = REPO / "config.json"
GLASSWING = REPO / "docs" / "glasswing.html"
DASHBOARD = REPO / "docs" / "dashboard.html"

PATTERN = re.compile(
    r"/\*BEGIN_MODEL_RUN_LOG\*/.*?/\*END_MODEL_RUN_LOG\*/",
    re.DOTALL,
)


def patch_glasswing(payload: str) -> bool:
    if not GLASSWING.exists():
        print(f"WARN: {GLASSWING} not found, skipping", file=sys.stderr)
        return False
    page = GLASSWING.read_text()
    if not PATTERN.search(page):
        print(f"ERROR: BEGIN/END_MODEL_RUN_LOG markers not found in {GLASSWING}", file=sys.stderr)
        return False
    replacement = f"/*BEGIN_MODEL_RUN_LOG*/{payload}/*END_MODEL_RUN_LOG*/"
    new_page = PATTERN.sub(lambda _m: replacement, page)
    if new_page == page:
        print(f"OK: {GLASSWING.name} already current")
        return False
    GLASSWING.write_text(new_page)
    print(f"OK: embedded {len(payload)} bytes of model-run-log into {GLASSWING.name}")
    return True


def compute_freeze_counter(log_obj: dict, freeze_date: str) -> dict:
    """Tally model-run events scored on or after the freeze date."""
    days_since = (date.today() - datetime.fromisoformat(freeze_date).date()).days
    runs = log_obj.get("runs") or []
    events_total = npdi_caught = dq_rescued = hacker_sa = union = missed = 0
    for run in runs:
        run_date = run.get("date")
        if not run_date or run_date < freeze_date:
            continue
        for ev in run.get("events") or []:
            events_total += 1
            np_di_raw = bool(ev.get("np")) and bool(ev.get("di"))
            dq_pass = (ev.get("dq_verdict") in ("pass", True)
                       and bool(ev.get("np")) and not bool(ev.get("di")))
            sa = (ev.get("hacker_tier") or "") in ("S", "A")
            if np_di_raw: npdi_caught += 1
            if dq_pass:   dq_rescued += 1
            if sa:        hacker_sa += 1
            caught = np_di_raw or dq_pass or sa
            if caught:    union += 1
            if ev.get("kev") and not caught:
                missed += 1
    return dict(
        days_since=max(days_since, 0),
        events_total=events_total,
        npdi_caught=npdi_caught,
        dq_rescued=dq_rescued,
        hacker_sa=hacker_sa,
        union=union,
        missed=missed,
    )


def patch_dashboard_freeze(counter: dict, freeze_date: str) -> bool:
    if not DASHBOARD.exists():
        print(f"WARN: {DASHBOARD} not found, skipping", file=sys.stderr)
        return False
    page = DASHBOARD.read_text()
    spans = {
        "freezeDate": freeze_date,
        "freezeDays": str(counter["days_since"]),
        "freezeEventsTotal": str(counter["events_total"]),
        "freezeNpdiCaught": str(counter["npdi_caught"]),
        "freezeDqRescued": str(counter["dq_rescued"]),
        "freezeHackerSA": str(counter["hacker_sa"]),
        "freezeUnion": str(counter["union"]),
        "freezeMissed": str(counter["missed"]),
    }
    new_page = page
    for span_id, value in spans.items():
        pat = re.compile(rf'(id="{span_id}"[^>]*>)([^<]*)(<)')
        new_page = pat.sub(lambda m, v=value: f"{m.group(1)}{v}{m.group(3)}", new_page)
    if new_page == page:
        print(f"OK: {DASHBOARD.name} freeze counter already current")
        return False
    DASHBOARD.write_text(new_page)
    print(f"OK: patched freeze counter in {DASHBOARD.name} → days={counter['days_since']}, events={counter['events_total']}, missed={counter['missed']}")
    return True


def main() -> int:
    if not LOG.exists():
        print(f"ERROR: {LOG} not found", file=sys.stderr)
        return 1

    log_obj = json.load(LOG.open())
    payload = json.dumps(log_obj, separators=(",", ":"))

    patch_glasswing(payload)

    if CONFIG.exists():
        cfg = json.load(CONFIG.open())
        freeze = cfg.get("di_cwe_freeze") or {}
        freeze_date = freeze.get("freeze_date")
        if freeze_date:
            counter = compute_freeze_counter(log_obj, freeze_date)
            patch_dashboard_freeze(counter, freeze_date)
        else:
            print("WARN: no di_cwe_freeze.freeze_date in config.json", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
