#!/usr/bin/env python3
"""Stream OSV all.zip per ecosystem, extract sub-7 CVSS records with CVE aliases."""
import json
import os
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORK = REPO / "data" / "_foss-sub7-cache"
WORK.mkdir(parents=True, exist_ok=True)
OSV_DIR = WORK / "osv_zips"
OSV_DIR.mkdir(exist_ok=True)
OUT_DIR = WORK / "osv_parsed"
OUT_DIR.mkdir(exist_ok=True)

ECOSYSTEMS = ["Maven", "npm", "PyPI", "Go", "RubyGems", "crates.io",
              "Packagist", "NuGet", "Hex"]

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

def parse_cvss_score(vector: str):
    """Parse CVSS v3.x base score from vector string. Returns float or None."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    # Use cvss library if available, else simple compute
    try:
        from cvss import CVSS3
        return CVSS3(vector).base_score
    except Exception:
        return None

def extract_cvss_v3(severity_list):
    """From OSV severity[], return (score, vector) if a CVSS_V3 (not V4) is present."""
    if not severity_list:
        return None, None
    for s in severity_list:
        t = s.get("type", "")
        score_str = s.get("score", "")
        if t in ("CVSS_V3", "CVSS_V3.1", "CVSS_V3.0"):
            sc = parse_cvss_score(score_str)
            if sc is not None:
                return sc, score_str
    return None, None

def extract_cvss_v4_fallback(severity_list):
    """Return CVSS_V4 score+vector if v3 not present (record but flag)."""
    if not severity_list:
        return None, None
    for s in severity_list:
        if s.get("type", "").startswith("CVSS_V4"):
            vec = s.get("score", "")
            try:
                from cvss import CVSS4
                return CVSS4(vec).base_score, vec
            except Exception:
                pass
    return None, None

def aliases_to_cve(aliases):
    if not aliases:
        return []
    return sorted({a for a in aliases if CVE_RE.match(a or "")})

def process_zip(zip_path: Path, ecosystem: str, out_path: Path, max_score: float = 7.0):
    """Yield matching records: CVSS<7, has CVE alias."""
    records = []
    seen_ids = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        print(f"  [{ecosystem}] {len(names)} entries")
        for name in names:
            if not name.endswith(".json"):
                continue
            seen_ids += 1
            try:
                with zf.open(name) as f:
                    rec = json.load(f)
            except Exception as e:
                continue
            sev = rec.get("severity") or []
            score, vec = extract_cvss_v3(sev)
            cvss_version = "v3"
            if score is None:
                # try v4 as last resort (still gating <7)
                score, vec = extract_cvss_v4_fallback(sev)
                cvss_version = "v4" if score is not None else None
            if score is None:
                continue
            if score >= max_score:
                continue
            if score <= 0:
                continue
            aliases = rec.get("aliases", [])
            cves = aliases_to_cve(aliases)
            if not cves:
                continue
            # Capture affected packages (limit to this ecosystem)
            pkgs = []
            for aff in rec.get("affected", []):
                pkg = aff.get("package", {}) or {}
                if pkg.get("ecosystem", "").lower() == ecosystem.lower():
                    pn = pkg.get("name")
                    if pn:
                        pkgs.append(pn)
            pkgs = sorted(set(pkgs))
            records.append({
                "osv_id": rec.get("id"),
                "ecosystem": ecosystem,
                "cves": cves,
                "packages": pkgs,
                "cvss_score": round(float(score), 1),
                "cvss_vector": vec,
                "cvss_version": cvss_version,
                "summary": (rec.get("summary") or "").strip()[:500],
                "details_excerpt": (rec.get("details") or "").strip()[:1500],
                "modified": rec.get("modified"),
                "published": rec.get("published"),
                "withdrawn": rec.get("withdrawn"),
            })
    print(f"  [{ecosystem}] {seen_ids} entries scanned, {len(records)} sub-7 with CVE")
    out_path.write_text(json.dumps(records, indent=1))
    return len(records)

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for eco in ECOSYSTEMS:
        if only and only != eco:
            continue
        zp = OSV_DIR / f"{eco}.zip"
        op = OUT_DIR / f"{eco}.json"
        if op.exists():
            print(f"[{eco}] already parsed -> {op}, skipping")
            continue
        print(f"[{eco}] downloading…")
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
        urllib.request.urlretrieve(url, zp)
        print(f"[{eco}] zip size: {zp.stat().st_size}")
        process_zip(zp, eco, op)
        zp.unlink()
        print(f"[{eco}] done")

if __name__ == "__main__":
    main()
