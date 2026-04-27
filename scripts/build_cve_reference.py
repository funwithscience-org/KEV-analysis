#!/usr/bin/env python3
"""
Build a single canonical per-CVE reference JSON by unioning every artifact
that contains per-CVE judgments under the threat-centric prioritization
model.

Sources (all relative to repo root):
  - data/retro-model-run-2026-03-27-to-04-26.json   (311 events; richest)
  - data/seven-year-manifest-events.json            (175 events; KEV/MSF/EDB)
  - data/seven-year-npdi-events.json                (101 events; OSV NP+DI)
  - data/retro-baseline-april-2022.json             ( 45 events; KEV baseline)
  - data/hacker-tiers.json                          ( 75 tier judgments)
  - data/waf-defensibility.json                     ( 13 WAF tags)
  - data/di-reclassification.json                   (  9 widened-DI events)
  - data/doc-canonical-npdi-events.json             ( 30 + 3 published events)
  - config.json exploit_watch_list.{server,desktop} ( 14 watch-list rows)
  - data/model-run-log.json (optional)              (analyst's daily log)
  - docs/cve-reference.html                         (legacy 127 static rows;
                                                     rescued so OS-container
                                                     CVEs not in any other
                                                     artifact are preserved)

Output: data/cve-reference.json with the schema documented in the rebuilt
docs/cve-reference.html. One row per unique CVE; provenance is recorded
in `sources` and meaningful conflicts are recorded in `conflicts`.

Usage:
    python3 scripts/build_cve_reference.py
    python3 scripts/build_cve_reference.py --check  # exit 1 if regen would change

The HTML page (docs/cve-reference.html) carries the same JSON inline in
a `<script id="cveReferenceData" type="application/json">` block; running
this script also patches that block so the page renders the latest data.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "data"
DOCS = REPO / "docs"

# Glasswing participants (mirrored from config.json glasswing_targets.participants)
# Loaded at runtime so it stays in sync.

# Round preference order (most recent first) for resolving tier conflicts.
ROUND_RANK = {
    "R9-retro": 90,
    "R8":       80,
    "R7":       70,
    "R6":       60,
    "R5":       50,
    "R4":       40,
    "R3":       30,
    None:        0,
}


def _load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with open(path) as f:
        return json.load(f)


def _norm_cve(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    # Skip non-CVE OSV ids when no CVE alias is known
    if not s.upper().startswith("CVE-"):
        return None
    return s.upper()


def _new_row(cve: str) -> dict:
    """Empty canonical row with all known fields."""
    return {
        "cve": cve,
        "vendor": None,
        "package": None,
        "ecosystem": None,
        "layer": None,
        "cwe": [],
        "cvss": None,
        "kev": None,
        "kev_date": None,
        "nvd_published": None,
        "in_metasploit": None,
        "in_exploitdb": None,
        "epss_day0": None,
        "epss_day7": None,
        "epss_day30": None,
        "ransomware": None,
        "np": None,
        "np_rationale": None,
        "di": None,
        "di_rationale": None,
        "dq_verdict": None,
        "hacker_tier": None,
        "tier_round": None,
        "tier_anchor": None,
        "hacker_rationale": None,
        "waf_defensibility": None,
        "waf_rationale": None,
        "combined_verdict": None,
        "currently_on_watchlist": False,
        "watchlist_status": None,
        "newly_caught_by_widening": None,
        "glasswing_participant_vendor": None,
        "description": None,
        "source": None,         # original "source" field from retro-run (kev/nvd/osv)
        "in_kev_window_count": None,
        "is_widened_di": None,
        "sources": [],
        "conflicts": [],
    }


# Fields where a name-variant disagreement is just normalization noise, not a
# substantive disagreement (e.g. "log4j-core" vs "org.apache.logging.log4j:log4j-core").
# We still take the first-source value but don't record the disagreement.
_QUIET_CONFLICT_FIELDS = {
    "package", "vendor", "description", "nvd_published", "cvss",
    "np_rationale", "di_rationale", "hacker_rationale", "waf_rationale",
    "watchlist_status", "kev_date",
}


def _merge_field(row: dict, key: str, value: Any, source: str, *,
                 prefer_truthy: bool = False) -> None:
    """Record a value into row[key]. If a different non-null value already
    exists, log a conflict and keep the first (sources are ordered by
    priority). When prefer_truthy is True, a truthy newcomer can replace a
    falsy current value (used for booleans like in_kev where False is the
    default and True is signal).

    Disagreements on free-text fields (package name, vendor, description)
    are common and not actually informative — the first-source value wins
    silently. Real conflicts (e.g. di=true vs di=false, hacker_tier S vs B)
    are recorded so the rebuilt page can surface them."""
    if value is None:
        return
    cur = row.get(key)
    if cur is None or cur == [] or cur == "":
        row[key] = value
        return
    if cur == value:
        return
    if prefer_truthy and not cur and value:
        # Truthy upgrade — silent, this is a refinement not a conflict
        row[key] = value
        return
    if key in _QUIET_CONFLICT_FIELDS:
        # Free-text disagreement — keep first, don't flag
        return
    # Real conflict — keep current, record disagreement
    row["conflicts"].append({
        "field": key,
        "from": source,
        "old_value": cur,
        "new_value": value,
        "resolution": "kept first-source value",
    })


def _add_source(row: dict, name: str) -> None:
    if name not in row["sources"]:
        row["sources"].append(name)


def _normalize_cwe(value: Any) -> list[str]:
    """Coerce a CWE field (string, int, list) into ['CWE-XX', ...]."""
    if value is None:
        return []
    if isinstance(value, int):
        return [f"CWE-{value}"]
    if isinstance(value, str):
        # Could be 'CWE-22, CWE-94' or 'CWE-22' or '22'
        out = []
        parts = re.split(r"[,;\s]+", value.strip())
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if p.isdigit():
                out.append(f"CWE-{p}")
            else:
                out.append(p.upper())
        return out
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_normalize_cwe(v))
        return out
    return []


def _normalize_severity(s: Any) -> Any:
    """Pass through a severity string or numeric CVSS score."""
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return s
    if isinstance(s, str):
        return s.upper()
    return s


# ──────────────────────────────────────────────────────────────────
# Source ingesters
# ──────────────────────────────────────────────────────────────────

def ingest_retro_model_run(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/retro-model-run-2026-03-27-to-04-26.json — 311 events.
    The richest source: full battery (np/di/dq/hacker/verdict)."""
    src = "retro-model-run-2026-03-27-to-04-26"
    data = _load_json(DATA / f"{src}.json", []) or []
    for ev in data:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "vendor", ev.get("vendor"), src)
        _merge_field(row, "package", ev.get("package"), src)
        _merge_field(row, "ecosystem", ev.get("ecosystem"), src)
        _merge_field(row, "layer", ev.get("layer"), src)
        _merge_field(row, "cvss", ev.get("cvss"), src)
        _merge_field(row, "nvd_published", ev.get("nvd_published"), src)
        _merge_field(row, "kev_date", ev.get("kev_date"), src)
        _merge_field(row, "kev", ev.get("kev"), src, prefer_truthy=True)
        _merge_field(row, "np", ev.get("np"), src)
        _merge_field(row, "np_rationale", ev.get("np_rationale"), src)
        _merge_field(row, "di", ev.get("di"), src)
        _merge_field(row, "di_rationale", ev.get("di_rationale"), src)
        _merge_field(row, "dq_verdict", ev.get("dq_verdict"), src)
        _merge_field(row, "hacker_tier", ev.get("hacker_tier"), src)
        _merge_field(row, "tier_anchor", ev.get("tier_anchor"), src)
        _merge_field(row, "hacker_rationale", ev.get("hacker_rationale"), src)
        _merge_field(row, "combined_verdict", ev.get("combined_verdict"), src)
        _merge_field(row, "currently_on_watchlist", ev.get("currently_on_watchlist"), src,
                     prefer_truthy=True)
        _merge_field(row, "newly_caught_by_widening", ev.get("newly_caught_by_widening"), src,
                     prefer_truthy=True)
        _merge_field(row, "description", ev.get("description"), src)
        _merge_field(row, "source", ev.get("source"), src)
        cwe = _normalize_cwe(ev.get("cwe"))
        if cwe and not row["cwe"]:
            row["cwe"] = cwe


def ingest_seven_year_manifest(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/seven-year-manifest-events.json — 175 events.
    Has in_kev / in_metasploit / in_exploitdb flags."""
    src = "seven-year-manifest-events"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    events = blob.get("events", []) or []
    for ev in events:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        # package(s) — choose the first NP role package as canonical, fall back to first
        pkgs = ev.get("packages", []) or []
        roles = ev.get("package_roles", []) or []
        primary_pkg = None
        for p, r in zip(pkgs, roles):
            if r == "NP":
                primary_pkg = p
                break
        if not primary_pkg and pkgs:
            primary_pkg = pkgs[0]
        if primary_pkg:
            _merge_field(row, "package", primary_pkg, src)
            # Infer ecosystem from package shape — the manifest doesn't carry
            # it explicitly, but Maven coords have ':' and others are bare.
            if ":" in primary_pkg and not row.get("ecosystem"):
                _merge_field(row, "ecosystem", "Maven", src)
        _merge_field(row, "nvd_published", ev.get("published"), src)
        _merge_field(row, "cvss", _normalize_severity(ev.get("severity")), src)
        _merge_field(row, "np", ev.get("is_np"), src)
        _merge_field(row, "di", ev.get("is_di"), src)
        _merge_field(row, "kev", ev.get("in_kev"), src, prefer_truthy=True)
        _merge_field(row, "in_metasploit", ev.get("in_metasploit"), src, prefer_truthy=True)
        _merge_field(row, "in_exploitdb", ev.get("in_exploitdb"), src, prefer_truthy=True)
        _merge_field(row, "description", ev.get("summary"), src)
        cwe = _normalize_cwe(ev.get("cwes") or ev.get("cwe_nums"))
        if cwe and not row["cwe"]:
            row["cwe"] = cwe


def ingest_seven_year_npdi(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/seven-year-npdi-events.json — 101 events. Includes EPSS day-0."""
    src = "seven-year-npdi-events"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    events = blob.get("events", []) or []
    for ev in events:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "package", ev.get("package"), src)
        _merge_field(row, "ecosystem", ev.get("ecosystem"), src)
        _merge_field(row, "nvd_published", ev.get("published"), src)
        _merge_field(row, "np", ev.get("is_np"), src)
        _merge_field(row, "di", ev.get("is_di"), src)
        _merge_field(row, "kev", ev.get("in_kev"), src, prefer_truthy=True)
        _merge_field(row, "in_metasploit", ev.get("in_metasploit"), src, prefer_truthy=True)
        _merge_field(row, "in_exploitdb", ev.get("in_exploitdb"), src, prefer_truthy=True)
        _merge_field(row, "description", ev.get("summary"), src)
        _merge_field(row, "epss_day0", ev.get("epss"), src)
        cwe = _normalize_cwe(ev.get("cwe"))
        if cwe and not row["cwe"]:
            row["cwe"] = cwe


def ingest_retro_baseline(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/retro-baseline-april-2022.json — 45 events. KEV-only April 2022."""
    src = "retro-baseline-april-2022"
    data = _load_json(DATA / f"{src}.json", []) or []
    for ev in data:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "vendor", ev.get("vendor"), src)
        _merge_field(row, "package", ev.get("product"), src)
        _merge_field(row, "kev", True, src, prefer_truthy=True)
        _merge_field(row, "kev_date", ev.get("date_added"), src)
        _merge_field(row, "np", ev.get("np"), src)
        _merge_field(row, "di", ev.get("di_inferred_from_text"), src)
        _merge_field(row, "dq_verdict", ev.get("dq_verdict"), src)
        _merge_field(row, "hacker_tier", ev.get("hacker_tier"), src)
        _merge_field(row, "hacker_rationale", ev.get("tier_rationale"), src)
        _merge_field(row, "combined_verdict", ev.get("combined_verdict"), src)
        _merge_field(row, "description", ev.get("short_description"), src)
        kr = ev.get("known_ransomware")
        if kr in ("Known", "known", True):
            _merge_field(row, "ransomware", True, src, prefer_truthy=True)
        elif kr in ("Unknown", "unknown", False):
            _merge_field(row, "ransomware", False, src)


def ingest_hacker_tiers(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/hacker-tiers.json — 75 tier judgments. R3-R9-retro.
    For tier conflicts, prefer the most recent round."""
    src = "hacker-tiers"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    tiers = blob.get("tiers", {}) or {}
    for cve, info in tiers.items():
        cve_n = _norm_cve(cve)
        if not cve_n:
            continue
        row = rows.setdefault(cve_n, _new_row(cve_n))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "package", info.get("package"), src)
        # Tier merge: prefer higher round rank
        new_round = info.get("round")
        new_tier = info.get("tier")
        cur_round = row.get("tier_round")
        if new_tier:
            if cur_round is None or ROUND_RANK.get(new_round, 0) >= ROUND_RANK.get(cur_round, 0):
                if row.get("hacker_tier") and row["hacker_tier"] != new_tier:
                    row["conflicts"].append({
                        "field": "hacker_tier",
                        "from": src,
                        "old_value": f"{row['hacker_tier']} ({cur_round or 'unknown'})",
                        "new_value": f"{new_tier} ({new_round})",
                        "resolution": f"took {new_round} (higher rank)",
                    })
                row["hacker_tier"] = new_tier
                row["tier_round"] = new_round
                if info.get("rationale"):
                    row["hacker_rationale"] = info["rationale"]
                if info.get("canonical_for"):
                    row["tier_anchor"] = info["canonical_for"]


def ingest_waf_defensibility(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    src = "waf-defensibility"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    events = blob.get("events", {}) or {}
    for cve, info in events.items():
        cve_n = _norm_cve(cve)
        if not cve_n:
            continue
        row = rows.setdefault(cve_n, _new_row(cve_n))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "waf_defensibility", info.get("waf"), src)
        _merge_field(row, "waf_rationale", info.get("rationale"), src)


def ingest_di_reclassification(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    src = "di-reclassification"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    additions = (blob.get("seven_year_backtest_additions", []) or []) \
              + (blob.get("twelve_month_backtest_additions", []) or [])
    for ev in additions:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        _merge_field(row, "package", ev.get("package"), src)
        _merge_field(row, "ecosystem", ev.get("ecosystem"), src)
        _merge_field(row, "nvd_published", ev.get("date"), src)
        _merge_field(row, "cvss", _normalize_severity(ev.get("severity")), src)
        _merge_field(row, "description", ev.get("summary"), src)
        cwe = _normalize_cwe(ev.get("cwes"))
        if cwe and not row["cwe"]:
            row["cwe"] = cwe
        included = ev.get("included")
        if included is True:
            _merge_field(row, "is_widened_di", True, src, prefer_truthy=True)
        else:
            _merge_field(row, "is_widened_di", False, src)
        if ev.get("rationale") and not row.get("di_rationale"):
            row["di_rationale"] = ev["rationale"]


def ingest_doc_canonical(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    src = "doc-canonical-npdi-events"
    blob = _load_json(DATA / f"{src}.json", {}) or {}
    main = blob.get("npdi_events", []) or []
    missed = blob.get("missed_exploited_events", []) or []
    for group, items in [("npdi_events", main), ("missed_exploited", missed)]:
        for ev in items:
            cve = _norm_cve(ev.get("cve"))
            if not cve:
                continue
            row = rows.setdefault(cve, _new_row(cve))
            _add_source(row, src)
            source_counts[src] = source_counts.get(src, 0) + 1
            _merge_field(row, "package", ev.get("library"), src)
            _merge_field(row, "nvd_published", ev.get("date"), src)
            _merge_field(row, "kev", ev.get("in_kev"), src, prefer_truthy=True)
            _merge_field(row, "in_metasploit", ev.get("in_metasploit"), src, prefer_truthy=True)
            if ev.get("notes"):
                if not row.get("description"):
                    row["description"] = ev["notes"]
            if ev.get("type") and not row.get("description"):
                row["description"] = ev["type"]
            if ev.get("is_widened_di"):
                _merge_field(row, "is_widened_di", True, src, prefer_truthy=True)


def ingest_watch_list(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    src = "config-watch-list"
    cfg = _load_json(REPO / "config.json", {}) or {}
    ewl = cfg.get("exploit_watch_list", {}) or {}
    for category in ("server", "desktop"):
        items = ewl.get(category, []) or []
        for w in items:
            cve = _norm_cve(w.get("cve"))
            if not cve:
                continue
            row = rows.setdefault(cve, _new_row(cve))
            _add_source(row, src)
            source_counts[src] = source_counts.get(src, 0) + 1
            row["currently_on_watchlist"] = True
            _merge_field(row, "package", w.get("product"), src)
            _merge_field(row, "watchlist_status", w.get("status"), src)
            if w.get("kevDate"):
                _merge_field(row, "kev", True, src, prefer_truthy=True)
                _merge_field(row, "kev_date", w.get("kevDate"), src)


def ingest_model_run_log(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """data/model-run-log.json — appended daily by analyst (optional, may be
    absent on a fresh repo). Newer entries override older ones for tier."""
    src = "model-run-log"
    path = DATA / f"{src}.json"
    if not path.exists():
        return
    raw = _load_json(path, []) or []
    # Format may be a list of {date, run_id, events:[...]} blocks, or a flat
    # list of events. Tolerate both.
    runs = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) and "events" in item:
                runs.append(item)
            elif isinstance(item, dict) and "cve" in item:
                # Flat list — treat as a single run
                runs.append({"date": None, "events": [item]})
    elif isinstance(raw, dict) and "events" in raw:
        runs.append(raw)
    # Sort by date ascending so the latest run wins
    runs.sort(key=lambda r: r.get("date") or "")
    for run in runs:
        for ev in run.get("events", []) or []:
            cve = _norm_cve(ev.get("cve"))
            if not cve:
                continue
            row = rows.setdefault(cve, _new_row(cve))
            _add_source(row, src)
            source_counts[src] = source_counts.get(src, 0) + 1
            _merge_field(row, "vendor", ev.get("vendor"), src)
            _merge_field(row, "package", ev.get("package"), src)
            _merge_field(row, "ecosystem", ev.get("ecosystem"), src)
            _merge_field(row, "layer", ev.get("layer"), src)
            _merge_field(row, "cvss", ev.get("cvss"), src)
            _merge_field(row, "nvd_published", ev.get("nvd_published"), src)
            _merge_field(row, "kev_date", ev.get("kev_date"), src)
            _merge_field(row, "kev", ev.get("kev"), src, prefer_truthy=True)
            _merge_field(row, "np", ev.get("np"), src)
            _merge_field(row, "di", ev.get("di"), src)
            _merge_field(row, "dq_verdict", ev.get("dq_verdict"), src)
            # Newer tier wins
            if ev.get("hacker_tier"):
                row["hacker_tier"] = ev["hacker_tier"]
                if ev.get("tier_anchor"):
                    row["tier_anchor"] = ev["tier_anchor"]
                if ev.get("hacker_rationale"):
                    row["hacker_rationale"] = ev["hacker_rationale"]
                row["tier_round"] = run.get("run_id") or row.get("tier_round")
            _merge_field(row, "combined_verdict", ev.get("combined_verdict"), src)
            _merge_field(row, "glasswing_participant_vendor",
                         ev.get("glasswing_participant_vendor"), src,
                         prefer_truthy=True)
            cwe = _normalize_cwe(ev.get("cwe"))
            if cwe and not row["cwe"]:
                row["cwe"] = cwe


# ──────────────────────────────────────────────────────────────────
# Legacy static-row rescue from docs/cve-reference.html
# ──────────────────────────────────────────────────────────────────

def ingest_legacy_static_rows(rows: dict[str, dict], source_counts: dict[str, int]) -> None:
    """Extract the 127 hand-coded rows from the prior version of
    docs/cve-reference.html, snapshotted to data/legacy-static-rows.json
    on 2026-04-27 when the page was rebuilt. These are the only on-record
    source for ~70 OS-container backport CVEs that aren't in any other
    artifact, so the snapshot has to live in data/, not in the live HTML
    (which now renders from cve-reference.json)."""
    src = "legacy-static-rows"
    blob = _load_json(DATA / "legacy-static-rows.json", {}) or {}
    eco_map = {
        "Spring Boot (Maven)":      ("Maven",   "app_framework"),
        "Node.js/Express (npm)":    ("npm",     "app_framework"),
        "Django/Python (PyPI)":     ("PyPI",    "app_framework"),
        "OS Container (AL2023)":    ("os",      "os"),
    }
    for ev in blob.get("rows", []) or []:
        cve = _norm_cve(ev.get("cve"))
        if not cve:
            continue
        row = rows.setdefault(cve, _new_row(cve))
        _add_source(row, src)
        source_counts[src] = source_counts.get(src, 0) + 1
        eco_norm, layer_norm = eco_map.get(ev.get("ecosystem_label", ""), (None, None))
        if eco_norm:
            _merge_field(row, "ecosystem", eco_norm, src)
        if layer_norm:
            _merge_field(row, "layer", layer_norm, src)
        _merge_field(row, "package", ev.get("package") or None, src)
        _merge_field(row, "nvd_published", ev.get("date") or None, src)
        _merge_field(row, "cvss", ev.get("severity") or None, src)
        cwe = _normalize_cwe(ev.get("cwes", ""))
        if cwe and not row["cwe"]:
            row["cwe"] = cwe
        _merge_field(row, "np", bool(ev.get("np")), src, prefer_truthy=True)
        _merge_field(row, "di", bool(ev.get("di")), src, prefer_truthy=True)
        _merge_field(row, "np_rationale", ev.get("reason") or None, src)


# ──────────────────────────────────────────────────────────────────
# Post-processing
# ──────────────────────────────────────────────────────────────────

def annotate_glasswing(rows: dict[str, dict], participants: list[str]) -> None:
    """Set glasswing_participant_vendor based on vendor matching the
    participants list. Uses substring match because vendor strings vary."""
    norm_parts = [p.strip().lower() for p in participants]
    for row in rows.values():
        if row.get("glasswing_participant_vendor") is True:
            continue
        v = (row.get("vendor") or "").lower()
        # Also check package/description hints — this is best-effort
        pk = (row.get("package") or "").lower()
        if any(p in v or p in pk for p in norm_parts):
            row["glasswing_participant_vendor"] = True
        else:
            # leave as None unless we already set False elsewhere
            pass


def derive_combined_verdict(rows: dict[str, dict]) -> None:
    """For rows that don't already have a combined_verdict, derive a best-
    effort one. The retro model run is authoritative when present; this
    is purely a fallback for rows from older artifacts."""
    for row in rows.values():
        if row.get("combined_verdict"):
            continue
        # Triggered: hacker S/A OR (NP + DI) OR (NP + DQ pass)
        tier = row.get("hacker_tier")
        np = row.get("np")
        di = row.get("di")
        dq = row.get("dq_verdict")
        if tier in ("S", "A"):
            row["combined_verdict"] = "triggered"
        elif np and di:
            row["combined_verdict"] = "triggered"
        elif np and dq == "pass":
            row["combined_verdict"] = "triggered"
        else:
            eco = row.get("ecosystem")
            if eco in ("Maven", "npm", "PyPI", "Go", "RubyGems", "crates.io",
                       "maven", "go", "rubygems", "pypi"):
                row["combined_verdict"] = "autobuild"
            elif eco in ("os", "appliance", "commercial") or row.get("layer") == "os":
                row["combined_verdict"] = "bau"
            else:
                row["combined_verdict"] = None  # unknown


def list_canonical_anchors() -> list[str]:
    """CVEs we never want to lose. If any of these go missing the test
    file flags it loudly."""
    return [
        "CVE-2021-44228",   # Log4Shell
        "CVE-2022-22965",   # Spring4Shell
        "CVE-2017-12615",   # Tomcat HTTP PUT
        "CVE-2017-12617",   # Tomcat HTTP PUT (Win)
        "CVE-2026-1340",    # Ivanti EPMM (canonical anchor)
        "CVE-2020-1938",    # Ghostcat
    ]


# ──────────────────────────────────────────────────────────────────
# HTML inline-data patching
# ──────────────────────────────────────────────────────────────────

_HTML_DATA_BLOCK_RE = re.compile(
    r'(<script id="cveReferenceData" type="application/json">)(.*?)(</script>)',
    re.DOTALL,
)


def slim_for_inline(payload: dict) -> dict:
    """Strip null/empty fields from each row to keep the inline JSON small.
    The full schema lives in data/cve-reference.json; the inline copy only
    needs the populated fields the renderer reads."""
    keep_top = {"generated_at", "generator", "n_cves", "n_with_conflicts",
                "canonical_anchors", "missing_anchors", "source_artifacts"}
    out = {k: payload[k] for k in keep_top if k in payload}
    slim_rows = []
    for r in payload.get("rows", []):
        sr = {}
        for k, v in r.items():
            # Always keep a few canonical anchors (helps debug)
            if k == "cve":
                sr[k] = v
                continue
            if v is None:
                continue
            if isinstance(v, (list, dict)) and not v:
                continue
            sr[k] = v
        slim_rows.append(sr)
    out["rows"] = slim_rows
    return out


def patch_html_inline_data(out_html: Path, payload: dict) -> bool:
    """Replace the <script id="cveReferenceData"> block in cve-reference.html
    with the latest JSON (slimmed). Returns True if the file was modified."""
    if not out_html.exists():
        return False
    text = out_html.read_text()
    payload_str = json.dumps(slim_for_inline(payload), separators=(",", ":"),
                             ensure_ascii=False)
    new_text, n = _HTML_DATA_BLOCK_RE.subn(
        lambda m: m.group(1) + "\n" + payload_str + "\n" + m.group(3),
        text,
        count=1,
    )
    if n == 0:
        return False
    if new_text != text:
        out_html.write_text(new_text)
        return True
    return False


# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────

def build() -> dict:
    rows: dict[str, dict] = {}
    counts: dict[str, int] = {}

    # Ingest in priority order. The first artifact to set a field "wins" by
    # default; later artifacts add provenance and may flag conflicts.
    ingest_retro_model_run(rows, counts)
    ingest_seven_year_manifest(rows, counts)
    ingest_seven_year_npdi(rows, counts)
    ingest_retro_baseline(rows, counts)
    ingest_di_reclassification(rows, counts)
    ingest_doc_canonical(rows, counts)
    ingest_hacker_tiers(rows, counts)        # tier-aware merge
    ingest_waf_defensibility(rows, counts)
    ingest_watch_list(rows, counts)
    ingest_legacy_static_rows(rows, counts)
    ingest_model_run_log(rows, counts)

    # Post-process
    cfg = _load_json(REPO / "config.json", {}) or {}
    participants = (cfg.get("glasswing_targets", {}) or {}).get("participants", []) or []
    annotate_glasswing(rows, participants)
    derive_combined_verdict(rows)

    # Canonical anchor sanity (warn but do not fail; the test will fail loudly)
    anchors = list_canonical_anchors()
    missing_anchors = [c for c in anchors if c not in rows]
    if missing_anchors:
        print(f"WARNING: missing canonical anchors: {missing_anchors}", file=sys.stderr)

    out_rows = sorted(rows.values(), key=lambda r: r["cve"])

    # Source-artifact summary in order of contribution
    source_artifacts = []
    for name, n in sorted(counts.items(), key=lambda x: -x[1]):
        source_artifacts.append({"artifact": name, "rows_contributed": n})

    payload = {
        "generated_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "scripts/build_cve_reference.py",
        "n_cves": len(out_rows),
        "n_with_conflicts": sum(1 for r in out_rows if r["conflicts"]),
        "canonical_anchors": anchors,
        "missing_anchors": missing_anchors,
        "source_artifacts": source_artifacts,
        "rows": out_rows,
    }
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description="Build data/cve-reference.json + patch HTML")
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regeneration would change the JSON or HTML.")
    ap.add_argument("--no-html", action="store_true",
                    help="Skip the inline-HTML patch step.")
    args = ap.parse_args()

    payload = build()

    out_path = DATA / "cve-reference.json"
    new_text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    cur_text = out_path.read_text() if out_path.exists() else ""

    out_html = DOCS / "cve-reference.html"

    if args.check:
        # Compare JSON
        try:
            cur_json = json.loads(cur_text) if cur_text else None
        except json.JSONDecodeError:
            cur_json = None
        # Re-serialize current with same formatting and compare ignoring generated_at
        def _strip_volatile(d: dict | None) -> dict | None:
            if not d:
                return d
            d = json.loads(json.dumps(d))
            d.pop("generated_at", None)
            return d
        if _strip_volatile(cur_json) != _strip_volatile(payload):
            print("FAIL: data/cve-reference.json is stale — re-run build_cve_reference.py")
            return 1
        # Compare HTML inline block (also ignoring generated_at inside the JSON blob)
        if out_html.exists():
            text = out_html.read_text()
            m = _HTML_DATA_BLOCK_RE.search(text)
            if m:
                try:
                    cur_inline = json.loads(m.group(2))
                    expected_inline = slim_for_inline(payload)
                    if _strip_volatile(cur_inline) != _strip_volatile(expected_inline):
                        print("FAIL: docs/cve-reference.html inline DATA is stale")
                        return 1
                except json.JSONDecodeError:
                    print("FAIL: docs/cve-reference.html inline DATA is not valid JSON")
                    return 1
        print(f"OK: cve-reference is current ({payload['n_cves']} rows)")
        return 0

    out_path.write_text(new_text)
    print(f"Wrote {out_path} ({payload['n_cves']} rows, "
          f"{payload['n_with_conflicts']} with conflicts)")

    if not args.no_html and out_html.exists():
        if patch_html_inline_data(out_html, payload):
            print(f"Patched inline DATA in {out_html}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
