"""Shared helpers for the numeric regression tests."""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# Fifteen canonical layers (must match data/kev-classifier.py)
LAYERS = {
    "os",
    "vpn_network_appliance",
    "jvm_runtime",
    "productivity_desktop",
    "email_collab_server",
    "browser",
    "iot_ics",
    "database",
    "virtualization_container",
    "library_framework",
    "cms_webapp",
    "web_server",
    "firmware_hardware",
    "ssl_tls_crypto",
    "other",
}

# Where the DATA blob lives in each HTML page. If these drift, the DATA extractor
# below will raise and every test in the suite will fail loudly — which is the
# intended behavior.
DATA_BLOB_SOURCES = [
    (REPO / "docs" / "dashboard.html", "const DATA = "),
    (REPO / "docs" / "index.html", "const DATA = "),
]


def load_classifications() -> dict:
    """Load data/kev-layer-classifications.json."""
    path = REPO / "data" / "kev-layer-classifications.json"
    with open(path) as f:
        return json.load(f)


def extract_data_blob(html_path: Path, prefix: str = "const DATA = ") -> dict:
    """Find the `const DATA = {...};` line in a page and return the parsed dict."""
    with open(html_path) as f:
        for line in f:
            if line.startswith(prefix):
                payload = line[len(prefix):].rstrip()
                if payload.endswith(";"):
                    payload = payload[:-1]
                return json.loads(payload)
    raise RuntimeError(f"No `{prefix}...` line found in {html_path}")


def all_data_blobs() -> list[tuple[Path, dict]]:
    """Return (path, data) for every published page with a DATA blob."""
    out = []
    for path, prefix in DATA_BLOB_SOURCES:
        out.append((path, extract_data_blob(path, prefix)))
    return out


def windowed(classifications: list[dict]) -> list[dict]:
    """CVEs published 2021 or later — the window used for all rate calcs."""
    return [r for r in classifications if r.get("year") and r["year"] >= 2021]


class TestReporter:
    """Minimal fail-loud reporter. Collects failures, exits 1 at the end."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.fails: list[str] = []
        self.checks = 0

    def check(self, condition: bool, message: str) -> None:
        self.checks += 1
        if not condition:
            self.fails.append(message)
            print(f"FAIL  {message}")

    def summary_exit_code(self) -> int:
        passed = self.checks - len(self.fails)
        status = "all green" if not self.fails else f"{len(self.fails)} FAILED"
        print(f"\n[{self.name}] {passed}/{self.checks} checks passed — {status}")
        return 1 if self.fails else 0
