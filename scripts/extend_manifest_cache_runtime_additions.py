#!/usr/bin/env python3
"""
Extend data/_manifest-osv-cache.json with the four runtime additions
from the user-supplied 7-year manifest:

  - Apache CXF        (org.apache.cxf:cxf, :cxf-core, plus key SOAP/JAX-RS/
                       JAX-WS submodules)
  - Apache MINA       (org.apache.mina:mina-core)
  - Apache SSHD       (org.apache.sshd:sshd-core, :sshd-common)
  - Hazelcast         (com.hazelcast:hazelcast)

Excluded from canonical (per user decision Option 2):
  - Pure build tooling (Maven core, plexus, surefire)
  - Dual-use scripting runtimes (Groovy, JRuby, Jython)

The "role" field is set explicitly so that
scripts/build_seven_year_manifest_events.py picks them up via the
standard role==NP rule (no further override list edits required for the
runtime additions).

Idempotent: running twice produces identical output (results are
deterministic — sorted vuln ids, fixed package keys).

Usage:
    python3 scripts/extend_manifest_cache_runtime_additions.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from urllib import request

REPO = Path(__file__).resolve().parent.parent
CACHE_PATH = REPO / "data" / "_manifest-osv-cache.json"

# Runtime additions: package coordinate -> role.
# All four packages are network parsers / network protocol surfaces:
#   - CXF         — SOAP/JAX-RS/JAX-WS HTTP frontend
#   - MINA        — async network framework (filter chain)
#   - SSHD        — SSH/SFTP server, parses untrusted SSH frames
#   - Hazelcast   — in-memory data grid; binary network protocol + REST
#
# CXF is split into the parent artifact (older CVEs) plus the modern
# per-module split. We include the modules with non-zero OSV vulns so
# the per-CVE event file has accurate package attribution.
RUNTIME_ADDITIONS = {
    "Maven/org.apache.cxf:cxf":                          "NP",
    "Maven/org.apache.cxf:cxf-core":                     "NP",
    "Maven/org.apache.cxf:cxf-rt-frontend-jaxrs":        "NP",
    "Maven/org.apache.cxf:cxf-rt-rs-security-jose":      "NP",
    "Maven/org.apache.cxf:cxf-rt-transports-http":       "NP",
    "Maven/org.apache.cxf:cxf-rt-ws-security":           "NP",
    "Maven/org.apache.mina:mina-core":                   "NP",
    "Maven/org.apache.sshd:sshd-core":                   "NP",
    "Maven/org.apache.sshd:sshd-common":                 "NP",
    "Maven/com.hazelcast:hazelcast":                     "NP",
}


def osv_query(ecosystem: str, name: str) -> list[dict]:
    body = json.dumps({
        "package": {"name": name, "ecosystem": ecosystem},
    }).encode()
    req = request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    return data.get("vulns", []) or []


def main() -> int:
    cache = json.load(open(CACHE_PATH))
    print(f"existing cache: {len(cache)} packages")

    added = 0
    updated = 0
    for key, role in RUNTIME_ADDITIONS.items():
        eco, name = key.split("/", 1)
        try:
            vulns = osv_query(eco, name)
        except Exception as e:
            print(f"  ERR  {key}: {e}", file=sys.stderr)
            return 1
        # Sort by id for determinism so re-runs hash-match.
        vulns_sorted = sorted(vulns, key=lambda v: v["id"])

        crit_high = [v for v in vulns_sorted
                     if (v.get("database_specific", {}).get("severity") or "").upper()
                     in ("CRITICAL", "HIGH")]
        if key in cache:
            updated += 1
            verb = "updated"
        else:
            added += 1
            verb = "added"
        cache[key] = {"role": role, "vulns": vulns_sorted}
        print(f"  {verb:7s} {key:55s} role={role:5s} "
              f"vulns={len(vulns_sorted):3d}  C/H={len(crit_high):3d}")
        # Polite pause to avoid rate limiting.
        time.sleep(0.4)

    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)
    print(f"\nwrote {CACHE_PATH.relative_to(REPO)}")
    print(f"  added:   {added}")
    print(f"  updated: {updated}")
    print(f"  total packages now: {len(cache)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
