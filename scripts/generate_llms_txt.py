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
# Canonical served URL. The site is on GitHub Pages but served via the
# funwithscience.net custom domain (org-wide CNAME pattern; KEV-analysis is
# a project subpath). The github.io URL still resolves but isn't canonical;
# sitemap and llms.txt point at the funwithscience.net URLs so search-console
# submissions match the verified property.
SITE = "https://funwithscience.net/KEV-analysis"
# GitHub repo URLs stay pointing at github.com — these reference the source
# code, not the served site.
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
    # Find the most-recent committed snapshot file (snapshots are stamped by
    # capture date, not catalog version — they don't always agree).
    snap_files = sorted(Path("data").glob("kev-snapshot-*.json"))
    if snap_files:
        snap_name = snap_files[-1].name
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
    if snap_files:
        parts.append(f"python3 data/kev-classifier.py --input data/{snap_files[-1].name} --no-snapshot")
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
        "# Allow all crawlers. The canonical robots.txt for the funwithscience.net\n"
        "# domain lives at the root of the org's main site; this file lives at the\n"
        "# project's subpath and documents project intent + points search engines\n"
        "# at the project sitemap and the LLM-friendly summary.\n"
        "User-agent: *\n"
        "Allow: /\n"
        "\n"
        f"Sitemap: {SITE}/sitemap.xml\n"
        "\n"
        f"# Machine-readable summary intended for LLMs:\n"
        f"# {SITE}/llms.txt\n"
    )


# --------------------------------------------------------------------------- #
# sitemap.xml
# --------------------------------------------------------------------------- #
# Pages to include in the sitemap. Order is intentional (most-important first).
# Skip v2 dead-draft files. Evergreen is a scratch/exploration page; included
# because it's linked from the main analysis and worth indexing for archive.
SITEMAP_PAGES: list[tuple[str, str, float]] = [
    # (path, changefreq, priority)
    ("index.html",            "weekly",  1.0),  # walkthrough — primary entry point
    ("dashboard.html",        "daily",   0.9),  # interactive dashboard, refresh agent updates daily
    ("periodicity.html",      "weekly",  0.9),
    ("build-mechanics.html",  "monthly", 0.8),
    ("cve-reference.html",    "weekly",  0.7),
    ("glasswing.html",        "weekly",  0.7),
    ("osv-exploitation.html", "monthly", 0.6),
    ("evergreen.html",        "monthly", 0.5),
    ("llms.txt",              "weekly",  0.4),
]


def render_sitemap_xml() -> str:
    today = dt.date.today().isoformat()
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for path, changefreq, priority in SITEMAP_PAGES:
        parts.append("  <url>")
        # Trailing slash for root index, no slash for sub-pages.
        loc = f"{SITE}/" if path == "index.html" else f"{SITE}/{path}"
        parts.append(f"    <loc>{loc}</loc>")
        parts.append(f"    <lastmod>{today}</lastmod>")
        parts.append(f"    <changefreq>{changefreq}</changefreq>")
        parts.append(f"    <priority>{priority}</priority>")
        parts.append("  </url>")
    parts.append("</urlset>")
    parts.append("")
    return "\n".join(parts)


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
    sitemap_path = REPO / "docs" / "sitemap.xml"

    new_llms = render_llms_txt(data, classif)
    new_robots = render_robots_txt()
    new_sitemap = render_sitemap_xml()

    if args.check:
        # The sitemap embeds today's date as <lastmod>, which makes byte-equal
        # comparison too brittle (every day would report drift even when nothing
        # else changed). Compare structure instead: ignore the lastmod lines.
        def strip_lastmod(s: str) -> str:
            return "\n".join(l for l in s.splitlines() if "<lastmod>" not in l)
        old_llms = llms_path.read_text() if llms_path.exists() else ""
        old_robots = robots_path.read_text() if robots_path.exists() else ""
        old_sitemap = sitemap_path.read_text() if sitemap_path.exists() else ""
        drift = []
        if old_llms != new_llms:
            drift.append(str(llms_path.relative_to(REPO)))
        if old_robots != new_robots:
            drift.append(str(robots_path.relative_to(REPO)))
        if strip_lastmod(old_sitemap) != strip_lastmod(new_sitemap):
            drift.append(str(sitemap_path.relative_to(REPO)))
        if drift:
            print(f"DRIFT: regenerating would change: {', '.join(drift)}")
            return 1
        print("OK: llms.txt, robots.txt, and sitemap.xml are up to date")
        return 0

    llms_path.write_text(new_llms)
    robots_path.write_text(new_robots)
    sitemap_path.write_text(new_sitemap)
    print(f"wrote {llms_path.relative_to(REPO)} ({len(new_llms):,} bytes)")
    print(f"wrote {robots_path.relative_to(REPO)} ({len(new_robots):,} bytes)")
    print(f"wrote {sitemap_path.relative_to(REPO)} ({len(new_sitemap):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
