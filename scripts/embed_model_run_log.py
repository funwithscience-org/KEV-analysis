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
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOG = REPO / "data" / "model-run-log.json"
PAGE = REPO / "docs" / "glasswing.html"

PATTERN = re.compile(
    r"/\*BEGIN_MODEL_RUN_LOG\*/.*?/\*END_MODEL_RUN_LOG\*/",
    re.DOTALL,
)


def main() -> int:
    if not LOG.exists():
        print(f"ERROR: {LOG} not found", file=sys.stderr)
        return 1
    if not PAGE.exists():
        print(f"ERROR: {PAGE} not found", file=sys.stderr)
        return 1

    payload_obj = json.load(LOG.open())
    payload = json.dumps(payload_obj, separators=(",", ":"))
    replacement = f"/*BEGIN_MODEL_RUN_LOG*/{payload}/*END_MODEL_RUN_LOG*/"

    page = PAGE.read_text()
    if not PATTERN.search(page):
        print(f"ERROR: BEGIN/END_MODEL_RUN_LOG markers not found in {PAGE}", file=sys.stderr)
        return 1

    # Use a lambda to avoid backslash interpretation in replacement (JSON has \u escapes)
    new_page = PATTERN.sub(lambda _m: replacement, page)
    if new_page == page:
        print(f"OK: {PAGE.name} already current ({len(payload)} bytes)")
        return 0

    PAGE.write_text(new_page)
    print(f"OK: embedded {len(payload)} bytes of model-run-log.json into {PAGE.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
