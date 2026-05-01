#!/usr/bin/env python3
"""
Compute the top_products field that drives the topProductsChart on
docs/dashboard.html.

Source: data/kev-snapshot-2026-05-01.json (full KEV catalog)

Per the prior AI's Q8 answer:
  - Group by KEV `vendorProject` + `product` strings
  - Some manual normalization (collapse Microsoft Windows variants)
  - Top 15 by count
  - Computed over the full KEV catalog (not windowed)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Manual normalization rules: KEV product strings can be slightly inconsistent
# across years. These rules collapse them to canonical names. Order matters
# for tie-breaking — first match wins.
NORMALIZATION_RULES: list[tuple[str, str]] = [
    # (substring or exact match in vendor+product, canonical name)
    ("Microsoft / Windows", "Microsoft Windows"),
    ("Microsoft / Win32k", "Microsoft Windows"),
    ("Microsoft / Internet Explorer", "Microsoft Internet Explorer"),
    ("Microsoft / Edge", "Microsoft Edge"),
    ("Microsoft / Office", "Microsoft Office"),
    ("Microsoft / Excel", "Microsoft Office"),
    ("Microsoft / Word", "Microsoft Office"),
    ("Microsoft / PowerPoint", "Microsoft Office"),
    ("Microsoft / Outlook", "Microsoft Office"),
    ("Microsoft / Exchange", "Microsoft Exchange"),
    ("Microsoft / SharePoint", "Microsoft SharePoint"),
    ("Apple / iOS", "Apple iOS / iPadOS"),
    ("Apple / iPadOS", "Apple iOS / iPadOS"),
    ("Apple / macOS", "Apple macOS"),
    ("Apple / Multiple Products", "Apple Multiple Products"),
    ("Apple / Safari", "Apple Safari/WebKit"),
    ("Apple / WebKit", "Apple Safari/WebKit"),
    ("Google / Chrome", "Google Chrome"),
    ("Google / Chromium", "Google Chrome"),
    ("Mozilla / Firefox", "Mozilla Firefox"),
    ("Adobe / Flash Player", "Adobe Flash Player"),
    ("Adobe / Acrobat", "Adobe Acrobat"),
    ("Adobe / Reader", "Adobe Acrobat"),
    ("Adobe / ColdFusion", "Adobe ColdFusion"),
    ("Linux / Kernel", "Linux Kernel"),
    ("Android / Framework", "Google Android"),
    ("Android / Pixel", "Google Android"),
    ("Android / Kernel", "Google Android"),
    ("Google / Android", "Google Android"),
    ("Samsung / Mobile Devices", "Samsung Mobile"),
    ("Apache / HTTP Server", "Apache HTTP Server"),
    ("Apache / Tomcat", "Apache Tomcat"),
    ("Apache / Struts", "Apache Struts"),
    ("Apache / Log4j", "Apache Log4j"),
    ("VMware / vCenter", "VMware vCenter"),
    ("VMware / ESXi", "VMware ESXi"),
    ("VMware / Spring Framework", "Spring Framework"),
    ("Cisco / IOS", "Cisco IOS"),
    ("Cisco / Adaptive Security Appliance", "Cisco ASA"),
    ("Fortinet / FortiOS", "Fortinet FortiOS"),
    ("Ivanti / Connect Secure", "Ivanti Connect Secure"),
    ("Ivanti / Endpoint Manager", "Ivanti EPM"),
    ("Citrix / NetScaler", "Citrix NetScaler"),
    ("Citrix / ADC", "Citrix NetScaler"),
    ("Citrix / Gateway", "Citrix NetScaler"),
    ("Palo Alto Networks / PAN-OS", "Palo Alto PAN-OS"),
]


def normalize(vendor: str, product: str) -> str:
    """Apply normalization rules to produce a canonical product name."""
    key = f"{vendor} / {product}"
    for needle, canonical in NORMALIZATION_RULES:
        if key.startswith(needle):
            return canonical
    return key  # No rule matched — use raw vendor/product as canonical


def build(top_n: int = 15) -> dict:
    snap_path = REPO / "data" / "kev-snapshot-2026-05-01.json"
    snap = json.load(open(snap_path))
    vulns = snap["vulnerabilities"]

    counter = Counter()
    for v in vulns:
        vendor = v.get("vendorProject", "").strip()
        product = v.get("product", "").strip()
        canonical = normalize(vendor, product)
        counter[canonical] += 1

    top = counter.most_common(top_n)
    top_products = [{"product": name, "count": count} for name, count in top]

    return {
        "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "description": (
            "Canonical top-products aggregation backing the topProductsChart "
            "on docs/dashboard.html. Counts are over the full KEV catalog, "
            "with manual normalization to collapse vendor/product variants."
        ),
        "methodology": {
            "source": str(snap_path.relative_to(REPO)),
            "scope": "full KEV catalog (all entries, all years)",
            "top_n": top_n,
            "normalization_rules": [
                {"if_starts_with": rule, "becomes": canonical}
                for rule, canonical in NORMALIZATION_RULES
            ],
            "fallback": "if no rule matches, use 'vendor / product' as canonical",
        },
        "summary": {
            "total_entries": len(vulns),
            "unique_canonical_products": len(counter),
            "top_n_share_pct": round(sum(c for _, c in top) / len(vulns) * 100, 1),
        },
        "top_products": top_products,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 if regenerating would change the on-disk file.")
    ap.add_argument("--top", type=int, default=15,
                    help="Number of top products to include (default 15)")
    args = ap.parse_args()

    out_path = REPO / "data" / "top-products.json"
    new = build(top_n=args.top)

    if args.check:
        if not out_path.exists():
            print(f"DRIFT: {out_path.relative_to(REPO)} does not exist")
            return 1
        old = json.load(open(out_path))
        for k in ("top_products", "methodology", "description", "summary"):
            if old.get(k) != new.get(k):
                print(f"DRIFT: {out_path.relative_to(REPO)} field {k!r} would change")
                return 1
        print(f"OK: {out_path.relative_to(REPO)} is up to date")
        return 0

    with open(out_path, "w") as f:
        json.dump(new, f, indent=2)
    print(f"wrote {out_path.relative_to(REPO)}")
    print(f"  total entries: {new['summary']['total_entries']}")
    print(f"  unique canonical: {new['summary']['unique_canonical_products']}")
    print(f"  top {args.top}:")
    for row in new["top_products"]:
        print(f"    {row['product']:35s} {row['count']:4d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
