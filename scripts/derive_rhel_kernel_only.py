#!/usr/bin/env python3
"""Derive a kernel-only view from the cached lifetime RHSA data.

Reads data/_rhel-lifetime-cache/csaf-YYYY.json (already pulled from Red Hat's
Security Data API by scripts/fetch_rhel_lifetime_advisories.py), filters to
advisories whose released_packages include kernel-* or kpatch-* packages,
and emits the same per-year + lifetime + first-N-years aggregates as the
parent script — but kernel-only.

Output: data/rhel-lifetime-kernel-advisories.json

This is the same input data as the all-package lifetime file, just with a
kernel-package gate. Same advisory can still appear under multiple major
versions if its packages span them.

Filter rule:
  - INCLUDE: package name starts with `kernel-` or `kpatch-` or is exactly
    `kernel` (covers kernel, kernel-core, kernel-rt, kernel-debug, kernel-
    modules*, kpatch-patch-*, etc.)
  - EXCLUDE: bpftool, perf userspace wrappers, libbpf, etc. — these are
    "kernel-adjacent" tools but not the kernel itself.

Run:
  python3 scripts/derive_rhel_kernel_only.py
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "data" / "_rhel-lifetime-cache"
OUT = REPO / "data" / "rhel-lifetime-kernel-advisories.json"

EL_RE = re.compile(r"\.el(\d+)[._-]")
# Kernel package = starts with "kernel-" OR "kpatch-" OR exactly "kernel"
# Strip NVR/arch suffix and check the first segment of the name.
KERNEL_NAME_RE = re.compile(r"^(kernel(-[a-z][a-z0-9_+-]*)?|kpatch(-[a-z][a-z0-9_+-]*)?)$")


def is_kernel_package(pkg_nvr: str) -> bool:
    """Detect kernel/kpatch packages from a released_packages NVR string.

    NVR format: name-version-release.arch  (e.g. 'kernel-0:5.14.0-503.40.1.el9_5.src')
    The leading 'name' segment may include hyphens (kernel-core, kernel-rt-debug, kpatch-patch-5_14_0_503_40_1).
    We split on `-N:` epoch or on the version-looking-segment to isolate the name.
    """
    # Strip leading epoch (e.g. "kernel-0:5.14.0-..." -> "kernel" name with 0: epoch)
    # Easiest: look for `-<digit>(.|:)` boundary which indicates start of version.
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9_+\-]*?)-\d", pkg_nvr)
    if not m:
        return False
    name = m.group(1)
    return bool(KERNEL_NAME_RE.match(name))


def classify_kernel_versions(adv: dict) -> set[int]:
    """Return RHEL major versions for which this advisory ships kernel/kpatch packages.

    An advisory might ship openssl on el7 + kernel on el8; only el8 counts as
    a kernel advisory in that case.
    """
    versions: set[int] = set()
    for p in adv.get("released_packages") or []:
        if not is_kernel_package(p):
            continue
        m = EL_RE.search(p)
        if m:
            v = int(m.group(1))
            if v in (6, 7, 8, 9, 10):
                versions.add(v)
    return versions


def main() -> int:
    if not CACHE.exists():
        print(f"ERROR: cache dir {CACHE} not found. Run fetch_rhel_lifetime_advisories.py first.", file=sys.stderr)
        return 1

    by_year_by_version: dict[str, dict[str, int]] = {}
    advisories_summary: list[dict] = []
    years_processed: list[int] = []

    for cache_file in sorted(CACHE.glob("csaf-*.json")):
        m = re.match(r"csaf-(\d{4})\.json", cache_file.name)
        if not m:
            continue
        year = int(m.group(1))
        years_processed.append(year)
        advs = json.load(cache_file.open())
        year_counts = {"6": 0, "7": 0, "8": 0, "9": 0, "10": 0}
        for adv in advs:
            kver = classify_kernel_versions(adv)
            if not kver:
                continue
            for v in kver:
                year_counts[str(v)] = year_counts.get(str(v), 0) + 1
            advisories_summary.append({
                "rhsa": adv.get("RHSA"),
                "year": year,
                "released_on": adv.get("released_on"),
                "severity": adv.get("severity"),
                "versions": sorted(kver),
                "cves": adv.get("CVEs", []),
            })
        by_year_by_version[str(year)] = year_counts
        print(f"[{year}] kernel-only: {year_counts}", file=sys.stderr)

    lifetime = {"6": 0, "7": 0, "8": 0, "9": 0, "10": 0}
    for y, counts in by_year_by_version.items():
        for v, n in counts.items():
            lifetime[v] = lifetime.get(v, 0) + n

    ga_year = {"6": 2010, "7": 2014, "8": 2019, "9": 2022, "10": 2025}
    end = max(years_processed)
    first_n_years: dict[str, list[int]] = {}
    for v, ga in ga_year.items():
        series = []
        for offset in range(0, end - ga + 1):
            y = str(ga + offset)
            series.append(by_year_by_version.get(y, {}).get(v, 0))
        first_n_years[v] = series

    out = {
        "schema_version": 1,
        "generated": date.today().isoformat(),
        "source": "Derived from data/_rhel-lifetime-cache/csaf-*.json (Red Hat Security Data API)",
        "filter": "released_packages contains a kernel-* or kpatch-* package built for the corresponding major version",
        "window": [min(years_processed), max(years_processed)],
        "ga_year": ga_year,
        "by_year_by_version": by_year_by_version,
        "lifetime_totals": lifetime,
        "first_n_years_per_version": first_n_years,
        "advisories": advisories_summary,
    }
    OUT.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {OUT}", file=sys.stderr)
    print(f"Kernel-only lifetime totals: {lifetime}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
