#!/usr/bin/env python3
"""
Fetch the Netty 12-month OSV data and build a Netty cache compatible with
the multi_framework_periodicity.json shape.

The Netty manifest per the prior AI's answer (Q2):
  - io.netty:netty-codec-http       (NP — HTTP codec)
  - io.netty:netty-codec-http2      (NP — HTTP/2 codec)
  - io.netty:netty-handler          (NP — SSL/TLS handler, channel pipeline)
  - io.netty:netty-transport        (OTHER — event loop, channels)
  - io.netty:netty-buffer           (OTHER — byte buffers)
  - io.netty:netty-common           (OTHER — utilities)
  - io.netty:netty-codec            (NP — parent codec, conservative)

Window: 2025-04-01 through 2026-04-30 (matches the other frameworks).

Output: data/_netty-osv-cache.json (same shape as a single-framework block
of multi_framework_periodicity.json).
"""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

def _load_netty_manifest() -> list[tuple[str, str, str]]:
    """Read Netty manifest from canonical data/manifests.json."""
    import json
    p = REPO / "data" / "manifests.json"
    raw = json.load(open(p))
    pkgs = raw["manifests"]["netty"]["packages"]
    return [(r["ecosystem"], r["package"], r["role"]) for r in pkgs]


NETTY_MANIFEST: list[tuple[str, str, str]] = _load_netty_manifest()

NP_PACKAGES = {pkg.split(":")[1] for eco, pkg, role in NETTY_MANIFEST if role == "NP"}
WINDOW_START = "2025-04-01"
WINDOW_END = "2026-04-30"


def query_osv(eco: str, pkg: str) -> list[dict]:
    body = json.dumps({"package": {"name": pkg, "ecosystem": eco}}).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query", data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("vulns", [])


def main() -> int:
    all_events = []
    for eco, full_pkg, role in NETTY_MANIFEST:
        short = full_pkg.split(":")[1]
        is_np = (role == "NP")
        print(f"  fetching {full_pkg}...", end=" ", flush=True)
        try:
            vulns = query_osv(eco, full_pkg)
        except Exception as e:
            print(f"ERROR: {e}")
            continue
        kept = 0
        for v in vulns:
            sev = v.get("database_specific", {}).get("severity", "").upper()
            if sev not in ("CRITICAL", "HIGH"):
                continue
            published = v.get("published", "")[:10]
            if not (WINDOW_START <= published <= WINDOW_END):
                continue
            cwe_strs = v.get("database_specific", {}).get("cwe_ids", []) or []
            aliases = v.get("aliases", [])
            primary_cve = next((a for a in aliases if a.startswith("CVE-")), None)
            all_events.append({
                "date": published,
                "vuln_id": v["id"],
                "aliases": aliases,
                "package": short,
                "full_package": f"{eco.lower()}/{full_pkg}",
                "severity": "HIGH/CRITICAL",
                "is_np": is_np,
                "is_di": False,  # filled in by classifier downstream
                "cwes": cwe_strs,
                "summary": v.get("summary", "")[:200],
                "primary_cve": primary_cve,
            })
            kept += 1
        print(f"{len(vulns)} total, {kept} in window")

    out = {
        "framework": "netty",
        "manifest_size": len(NETTY_MANIFEST),
        "manifest": [{"ecosystem": e, "package": p, "role": r}
                     for e, p, r in NETTY_MANIFEST],
        "np_count": len([m for m in NETTY_MANIFEST if m[2] == "NP"]),
        "other_count": len([m for m in NETTY_MANIFEST if m[2] == "OTHER"]),
        "all_events": all_events,
        "window_start": WINDOW_START,
        "window_end": WINDOW_END,
        "fetched_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }

    out_path = REPO / "data" / "_netty-osv-cache.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {out_path.relative_to(REPO)}: {len(all_events)} events")
    print(f"  Unique dates: {len(set(e['date'] for e in all_events))}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
