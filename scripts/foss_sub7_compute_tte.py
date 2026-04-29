#!/usr/bin/env python3
"""Compute time-to-exploit for the FOSS sub-7 server-side exploited dataset.

For each CVE in data/foss-sub7-exploited.json, the script joins against:
  - CISA KEV (dateAdded)
  - ExploitDB CSV (date_published per alias-listed CVE)
  - Metasploit modules (disclosure_date for any module referencing the CVE)
and writes the per-CVE earliest-exploit-evidence date and TTE in days
(measured from a best-effort CVE publication baseline).

Output: data/foss-sub7-tte.json
  {
    "schema_version": 1,
    "baseline_publish_logic": "...",
    "summary": {
      "n_with_tte": ...,
      "median_days": ...,
      "p25_days": ..., "p75_days": ..., "mean_days": ...,
      "by_evidence": {"KEV": {...}, "Metasploit": {...}, "ExploitDB": {...}},
      "by_year": {"2021": {...}, ...}
    },
    "by_cve": {
      "CVE-YYYY-NNNN": {
        "publish_date": "YYYY-MM-DD",
        "publish_basis": "osv_published" | "cve_year_jan1",
        "first_exploit_date": "YYYY-MM-DD",
        "first_exploit_source": "KEV" | "Metasploit" | "ExploitDB",
        "tte_days": <int>
      }, ...
    }
  }

Inputs (cached locally; re-pulled on demand):
  data/_foss-sub7-cache/kev.json
  data/_foss-sub7-cache/files_exploits.csv
  data/_foss-sub7-cache/modules_metadata_base.json

Run:
  python3 scripts/foss_sub7_compute_tte.py [--refresh]

The script is idempotent and reproducible. Re-running with --refresh forces
re-downloads of KEV / ExploitDB / Metasploit; otherwise it uses the cached
copies if present.
"""
from __future__ import annotations

import csv
import json
import re
import sys
import urllib.request
from datetime import date, datetime
from pathlib import Path
from statistics import median, mean

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "data" / "_foss-sub7-cache"
CACHE.mkdir(parents=True, exist_ok=True)
DATASET = REPO / "data" / "foss-sub7-exploited.json"
OUT = REPO / "data" / "foss-sub7-tte.json"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = CACHE / "kev.json"
MSF_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
MSF_CACHE = CACHE / "modules_metadata_base.json"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EDB_CACHE = CACHE / "files_exploits.csv"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def fetch(url: str, dest: Path, refresh: bool = False) -> Path:
    if dest.exists() and not refresh:
        return dest
    print(f"  fetching {url} → {dest.name}", file=sys.stderr)
    req = urllib.request.Request(url, headers={"User-Agent": "KEV-analysis/foss-sub7-tte"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as fh:
        fh.write(resp.read())
    return dest


def load_kev_dates(path: Path) -> dict[str, str]:
    """{cveID: dateAdded YYYY-MM-DD}"""
    data = json.load(path.open())
    return {v["cveID"]: v["dateAdded"] for v in data.get("vulnerabilities", []) if v.get("dateAdded")}


def load_msf_dates(path: Path) -> dict[str, list[str]]:
    """{cve: [disclosure_date, ...]} — collect all module disclosure dates per CVE."""
    data = json.load(path.open())
    out: dict[str, list[str]] = {}
    for mod in data.values():
        d = mod.get("disclosure_date")
        if not d:
            continue
        for ref in mod.get("references", []):
            m = CVE_RE.search(ref or "")
            if m:
                out.setdefault(m.group(0), []).append(d)
    return out


def load_edb_dates(path: Path) -> dict[str, list[str]]:
    """{cve: [date_published, ...]} — collect ExploitDB publish dates per aliased CVE.

    Filters to non-DoS, non-PoC entries to match the original scan logic.
    """
    out: dict[str, list[str]] = {}
    poc_re = re.compile(r"proof[ -]?of[ -]?concept|PoC", re.I)
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if (row.get("type") or "").lower() == "dos":
                continue
            if poc_re.search(row.get("description") or ""):
                continue
            for alias in (row.get("codes") or "").split(";"):
                m = CVE_RE.search(alias.strip())
                if not m:
                    continue
                d = row.get("date_published")
                if d:
                    out.setdefault(m.group(0), []).append(d)
    return out


def cve_year(cve: str) -> int:
    return int(cve.split("-")[1])


def best_baseline(rec: dict) -> tuple[str, str]:
    """Return (publish_date, basis) for a record.

    Prefer OSV published if it falls within ~12 months of the CVE year;
    otherwise back off to Jan 1 of the CVE year (gives an upper-bound TTE,
    so a long TTE can't be inflated by a delayed OSV ingest of an old CVE).
    """
    cve = rec["cve"]
    yr = cve_year(cve)
    osv_pub = rec.get("osv_published")
    if osv_pub:
        try:
            d = datetime.fromisoformat(osv_pub.replace("Z", "+00:00")).date()
            if d.year >= yr - 1 and d.year <= yr + 1:
                return d.isoformat(), "osv_published"
        except Exception:
            pass
    return f"{yr}-01-01", "cve_year_jan1"


def parse_d(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except Exception:
            return None


def percentile(vals: list[int], p: float) -> int:
    """Approximate percentile (linear interpolation, no numpy dependency)."""
    if not vals:
        return 0
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return int(s[f])
    return int(s[f] + (s[c] - s[f]) * (k - f))


def stat_block(vals: list[int]) -> dict:
    if not vals:
        return {"n": 0}
    return {
        "n": len(vals),
        "median_days": int(median(vals)),
        "p25_days": percentile(vals, 0.25),
        "p75_days": percentile(vals, 0.75),
        "mean_days": int(mean(vals)),
        "min_days": min(vals),
        "max_days": max(vals),
    }


def main() -> int:
    refresh = "--refresh" in sys.argv

    # Pull or load cached source files
    print("Loading exploit-date sources…", file=sys.stderr)
    fetch(KEV_URL, KEV_CACHE, refresh)
    fetch(MSF_URL, MSF_CACHE, refresh)
    fetch(EDB_URL, EDB_CACHE, refresh)

    kev_dates = load_kev_dates(KEV_CACHE)
    msf_dates = load_msf_dates(MSF_CACHE)
    edb_dates = load_edb_dates(EDB_CACHE)

    rows = json.load(DATASET.open())
    by_cve: dict[str, dict] = {}

    # Collapse the per-package rows to per-CVE; pick first hit
    seen_cve: set[str] = set()
    for r in rows:
        cve = r["cve"]
        if cve in seen_cve:
            continue
        seen_cve.add(cve)

        publish_date, publish_basis = best_baseline(r)
        publish_d = parse_d(publish_date)

        # Find earliest exploit evidence date
        candidates: list[tuple[date, str]] = []
        if cve in kev_dates:
            d = parse_d(kev_dates[cve])
            if d:
                candidates.append((d, "KEV"))
        if cve in msf_dates:
            for s in msf_dates[cve]:
                d = parse_d(s)
                if d:
                    candidates.append((d, "Metasploit"))
        if cve in edb_dates:
            for s in edb_dates[cve]:
                d = parse_d(s)
                if d:
                    candidates.append((d, "ExploitDB"))

        if not candidates:
            by_cve[cve] = {
                "publish_date": publish_date,
                "publish_basis": publish_basis,
                "first_exploit_date": None,
                "first_exploit_source": None,
                "tte_days": None,
                "tte_excluded": "no_exploit_date_found",
            }
            continue

        candidates.sort(key=lambda x: x[0])
        first_d, first_src = candidates[0]
        tte = (first_d - publish_d).days if publish_d else None

        # Negative TTE happens when ExploitDB is older than OSV's first record
        # (genuine: 0-day published, OSV catalogued months later). Floor to 0
        # but flag it so the data guy can audit.
        flag = None
        if tte is not None and tte < 0:
            flag = "negative_clamped_to_0"
            tte = 0

        by_cve[cve] = {
            "publish_date": publish_date,
            "publish_basis": publish_basis,
            "first_exploit_date": first_d.isoformat(),
            "first_exploit_source": first_src,
            "tte_days": tte,
            "tte_flag": flag,
            "evidence_sources": r.get("evidence_sources", []),
            "cvss_score": r.get("cvss_score"),
            "ecosystem": r.get("ecosystem"),
        }

    # Aggregate
    valid = [v["tte_days"] for v in by_cve.values() if v.get("tte_days") is not None]
    by_evidence: dict[str, list[int]] = {"KEV": [], "Metasploit": [], "ExploitDB": []}
    by_year: dict[str, list[int]] = {}
    for cve, v in by_cve.items():
        if v.get("tte_days") is None:
            continue
        src = v.get("first_exploit_source")
        if src in by_evidence:
            by_evidence[src].append(v["tte_days"])
        yr = str(cve_year(cve))
        by_year.setdefault(yr, []).append(v["tte_days"])

    out = {
        "schema_version": 1,
        "generated": date.today().isoformat(),
        "baseline_publish_logic": "OSV published date if within ±1 year of CVE-YYYY year; else Jan 1 of CVE year (upper-bound TTE for delayed-ingest cases).",
        "first_exploit_logic": "earliest of KEV dateAdded, Metasploit module disclosure_date, ExploitDB date_published (after dropping DoS-only and PoC-only entries).",
        "n_distinct_cves": len(by_cve),
        "n_with_tte": len(valid),
        "summary": {
            "all": stat_block(valid),
            "by_evidence": {k: stat_block(v) for k, v in by_evidence.items()},
            "by_year": {k: stat_block(v) for k, v in sorted(by_year.items())},
        },
        "ch_baseline_for_comparison": {
            "_doc": "C/H baseline from docs/dashboard.html — KEV-confirmed C/H entries, days from CVE publish to KEV-listing, by publish year. Mediums-vs-C/H comparison is the point of this analysis.",
            "by_year": {
                "2021": {"n": 88, "median_days": 251, "p25_days": 160, "p75_days": 360, "mean_days": 363},
                "2022": {"n": 39, "median_days": 61,  "p25_days": 14,  "p75_days": 194, "mean_days": 177},
                "2023": {"n": 44, "median_days": 11,  "p25_days": 3,   "p75_days": 155, "mean_days": 141},
                "2024": {"n": 22, "median_days": 34,  "p25_days": 1,   "p75_days": 64,  "mean_days": 61},
            },
        },
        "by_cve": by_cve,
    }

    OUT.write_text(json.dumps(out, indent=2))
    print(f"Wrote {OUT}")
    print(f"  n_distinct_cves: {len(by_cve)}, n_with_tte: {len(valid)}")
    print(f"  all-CVE TTE: {stat_block(valid)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
