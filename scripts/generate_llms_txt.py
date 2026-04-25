#!/usr/bin/env python3
"""
Generate docs/llms.txt and docs/robots.txt from the live data files.

Pure function of:
  - data/kev-layer-classifications.json (per-entry classifications + summary)
  - docs/dashboard.html DATA blob (for total_kev, layer rates, ransomware)

Run by the refresh agent after each nightly classifier-aware update.
The output is committed to the repo so non-JS clients (LLMs, search
engines, scrapers) get a fresh static snapshot of the headline numbers
even though the HTML pages compute them at page load.

Usage:
    python3 scripts/generate_llms_txt.py              # writes both files
    python3 scripts/generate_llms_txt.py --check      # exit 1 if regen would change them
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SITE = "https://funwithscience-org.github.io/KEV-analysis"
GITHUB = "https://github.com/funwithscience-org/KEV-analysis/blob/main"
RAW = "https://raw.githubusercontent.com/funwithscience-org/KEV-analysis/main"


def load_data_blob(html_path: Path) -> dict:
    with open(html_path) as f:
        for line in f:
            if line.startswith("const DATA = "):
                payload = line[len("const DATA = "):].rstrip()
                if payload.endswith(";"):
                    payload = payload[:-1]
                return json.loads(payload)
    raise RuntimeError(f"No DATA blob in {html_path}")


def load_classifications() -> dict:
    return json.load(open(REPO / "data" / "kev-layer-classifications.json"))


# --------------------------------------------------------------------------- #
# llms.txt
# --------------------------------------------------------------------------- #
def render_llms_txt(data: dict, classif: dict) -> str:
    summary = classif.get("summary", {})
    catalog_version = classif.get("kev_catalog_version", "unknown")
    today = dt.date.today().isoformat()

    nvd_total = sum(x["nvd"] for x in data["layer_data"])
    kev_windowed = sum(x["kev"] for x in data["layer_data"])
    kev_total = data["total_kev"]
    pre_window = kev_total - kev_windowed
    exploit_rate = kev_windowed / nvd_total * 100
    ransomware_windowed = data["ransomware_count"]

    # Layer table (sorted by rate desc, exclude 'other' which is a residual)
    rows = sorted(
        (r for r in data["layer_data"] if r["layer"] != "other"),
        key=lambda r: -r["rate"],
    )

    # Headline buckets
    os_row = next(r for r in data["layer_data"] if r["layer"] == "os")
    fw_row = next(r for r in data["layer_data"] if r["layer"] == "firmware_hardware")
    em_row = next(r for r in data["layer_data"] if r["layer"] == "email_collab_server")

    parts: list[str] = []
    parts.append("# KEV Analysis")
    parts.append("")
    parts.append(
        "> Empirical analysis of which security vulnerabilities actually get "
        "exploited in the wild, and which don't. Built from the CISA Known "
        "Exploited Vulnerabilities (KEV) catalog and NVD critical/high CVEs, "
        "with network-parsing components identified as a 3-6x exploitation "
        "predictor at every CVSS severity level."
    )
    parts.append("")
    parts.append(
        f"This file is a machine-readable summary intended for LLMs, scrapers, "
        f"and other non-interactive consumers. The interactive HTML pages "
        f"compute their numbers from the same DATA blob at page load; this "
        f"file mirrors the latest values as a static snapshot, regenerated "
        f"by the nightly refresh agent. Last updated: {today} "
        f"(catalog version {catalog_version})."
    )
    parts.append("")

    # Headline numbers
    parts.append("## Headline numbers (current)")
    parts.append("")
    parts.append(f"- {kev_total:,} total CISA KEV entries")
    parts.append(
        f"- {kev_windowed:,} of those target CVEs published 2021-2026 "
        f"(the analysis window)"
    )
    parts.append(
        f"- {pre_window:,} additional KEV entries target older CVEs "
        f"(excluded from rates)"
    )
    parts.append(
        f"- {nvd_total:,} NVD critical/high CVEs published 2021-2026 "
        f"(the denominator)"
    )
    parts.append(f"- {exploit_rate:.1f}% overall exploitation rate")
    parts.append(
        f"- {os_row['rate']:.1f}% OS exploitation rate (highest layer; the "
        f"NVD-321 denominator may be narrower than the KEV os bucket which "
        f"sweeps Microsoft, Apple, Android, and Linux)"
    )
    parts.append(
        f"- {fw_row['rate']:.2f}% firmware/hardware exploitation rate "
        f"({fw_row['kev']} of {fw_row['nvd']:,})"
    )
    parts.append(
        f"- {em_row['rate']:.1f}% email/collaboration server rate "
        f"({em_row['kev']}/{em_row['nvd']}; small NVD denominator, "
        f"treat as upper-bound artifact)"
    )
    parts.append(
        f"- {ransomware_windowed} windowed KEV entries linked to known "
        f"ransomware campaigns (~{ransomware_windowed/kev_windowed*100:.0f}% "
        f"of windowed total)"
    )
    parts.append(
        "- 3-6x lift for network-parsing CVEs vs. non-parsing CVEs at the "
        "same CVSS severity (the central thesis)"
    )
    parts.append("")

    # Per-layer table
    parts.append("## Per-layer exploitation (windowed 2021-2026)")
    parts.append("")
    parts.append("| Layer | KEV | NVD | Rate |")
    parts.append("|---|---:|---:|---:|")
    for r in rows:
        parts.append(
            f"| {r['layer']} | {r['kev']:,} | {r['nvd']:,} | {r['rate']:.2f}% |"
        )
    other = next(r for r in data["layer_data"] if r["layer"] == "other")
    parts.append(
        f"| other | {other['kev']:,} | {other['nvd']:,} | {other['rate']:.2f}% |"
    )
    parts.append("")
    parts.append(
        "Sums: layer KEV totals "
        f"= {sum(x['kev'] for x in data['layer_data']):,} "
        "(matches windowed total above). NVD denominators are inherited from "
        "the original analysis and are held fixed; KEV numerators update "
        "when the classifier re-runs against a new snapshot."
    )
    parts.append("")

    # Methodology
    parts.append("## Methodology")
    parts.append("")
    parts.append(
        "KEV is windowed to CVEs published 2021+ to align with the NVD "
        "denominator window (CVEs published 2021-2026). The numerator and "
        "denominator now agree on year scope. Per-entry layer assignment is "
        "produced by a deterministic first-match-wins classifier across "
        "fifteen layers."
    )
    parts.append("")
    parts.append(f"- Classifier source: [data/kev-classifier.py]({GITHUB}/data/kev-classifier.py)")
    parts.append(f"- Per-entry classifications (JSON): [{RAW}/data/kev-layer-classifications.json]({RAW}/data/kev-layer-classifications.json)")
    if catalog_version != "unknown":
        snap_name = f"kev-snapshot-{catalog_version.replace('.', '-')}.json"
        parts.append(f"- Pinned input snapshot (JSON): [{RAW}/data/{snap_name}]({RAW}/data/{snap_name})")
    parts.append(f"- Classifier documentation: [data/CLASSIFIER.md]({GITHUB}/data/CLASSIFIER.md)")
    parts.append(f"- Numeric regression test suite: [tests/]({GITHUB}/tests)")
    parts.append("")

    # Pages
    parts.append("## Pages")
    parts.append("")
    parts.append(f"- [Walkthrough]({SITE}/index.html): long-form analysis with sidebar navigation")
    parts.append(f"- [Dashboard]({SITE}/dashboard.html): interactive Chart.js dashboard")
    parts.append(f"- [Periodicity]({SITE}/periodicity.html): cross-framework backtest of the NP+DI filter")
    parts.append(f"- [Build Mechanics]({SITE}/build-mechanics.html): operational layer — BAU vs floor sweeps, the cat 1/2/3 estate-maturity model (with a 1/3-1/3-1/3 worked example), WAFs as spackle, filter value by response shape, and a practical-implications section on enterprise rules (auth-posture metadata, filter scope by auth posture, the Spring Boot Actuator/Jolokia case, hygiene rules, and a CVE triage decision flow)")
    parts.append(f"- [CVE Reference]({SITE}/cve-reference.html): per-CVE classification table")
    parts.append(f"- [Glasswing]({SITE}/glasswing.html): speculative analysis of AI-discovered CVEs (intelligence assessment, not data)")
    parts.append(f"- [OSV Exploitation]({SITE}/osv-exploitation.html): open-source library exploitation analysis using OSV.dev")
    parts.append("")

    # Caveats
    parts.append("## Caveats and limitations")
    parts.append("")
    parts.append(
        "- NVD denominators were derived at a prior point and may be stale. "
        "If a layer's KEV count exceeds its NVD count, that's a "
        "denominator-drift signal, not a methodology failure."
    )
    parts.append(
        "- email_collab_server at exactly 100% (44/44) is on the edge of the "
        "inherited NVD denominator. Any new email/collab KEV entry will tip "
        "the rate above 100% until the NVD denominator is refreshed."
    )
    parts.append(
        "- The classifier is rule-based and first-match-wins. Different rule "
        "orderings would produce different counts. Reproducibility is the "
        "guarantee, not objective ground truth."
    )
    parts.append(
        "- KEV is U.S.-government and enterprise-biased and undercounts "
        "open-source library exploitation. For library-specific analysis, "
        "prefer OSV.dev (which we use on the OSV Exploitation page)."
    )
    parts.append(
        "- The 3-6x network-parsing lift is the conservative claim; "
        "windowed data shows 3.7-7.0x. The widened DI CWE set and the AI "
        "scan tier are documented in the periodicity page methodology."
    )
    parts.append("")

    # Reproduce
    parts.append("## How to reproduce")
    parts.append("")
    parts.append("```")
    parts.append("git clone https://github.com/funwithscience-org/KEV-analysis")
    parts.append("cd KEV-analysis")
    if catalog_version != "unknown":
        snap = f"data/kev-snapshot-{catalog_version.replace('.', '-')}.json"
        parts.append(f"python3 data/kev-classifier.py --input {snap} --no-snapshot")
    else:
        parts.append("python3 data/kev-classifier.py")
    parts.append("bash tests/run.sh             # full numeric regression suite")
    parts.append("bash tests/run.sh --full      # also re-classify the pinned snapshot")
    parts.append("```")
    parts.append("")

    # Source
    parts.append("## Source")
    parts.append("")
    parts.append("- Repository: https://github.com/funwithscience-org/KEV-analysis")
    parts.append("- License: see repository")
    parts.append("- Schedule: refresh agent runs nightly at 5:03 AM UTC; analyst agent at 6:10 AM UTC")
    parts.append("")

    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# robots.txt
# --------------------------------------------------------------------------- #
def render_robots_txt() -> str:
    return (
        "# Allow all crawlers. The canonical robots.txt for github.io is\n"
        "# controlled by GitHub; this file documents project intent and\n"
        "# points to the LLM-friendly summary.\n"
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        f"# Machine-readable summary intended for LLMs:\n"
        f"# {SITE}/llms.txt\n"
    )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if regenerating would change the on-disk file (CI-friendly).",
    )
    args = ap.parse_args()

    classif = load_classifications()
    data = load_data_blob(REPO / "docs" / "dashboard.html")

    llms_path = REPO / "docs" / "llms.txt"
    robots_path = REPO / "docs" / "robots.txt"

    new_llms = render_llms_txt(data, classif)
    new_robots = render_robots_txt()

    if args.check:
        old_llms = llms_path.read_text() if llms_path.exists() else ""
        old_robots = robots_path.read_text() if robots_path.exists() else ""
        drift = []
        if old_llms != new_llms:
            drift.append(str(llms_path.relative_to(REPO)))
        if old_robots != new_robots:
            drift.append(str(robots_path.relative_to(REPO)))
        if drift:
            print(f"DRIFT: regenerating would change: {', '.join(drift)}")
            return 1
        print("OK: llms.txt and robots.txt are up to date")
        return 0

    llms_path.write_text(new_llms)
    robots_path.write_text(new_robots)
    print(f"wrote {llms_path.relative_to(REPO)} ({len(new_llms):,} bytes)")
    print(f"wrote {robots_path.relative_to(REPO)} ({len(new_robots):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
