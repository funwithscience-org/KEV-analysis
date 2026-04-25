#!/usr/bin/env python3
"""
Regression tests for data/kev-classifier.py.

Two modes:

    python tests/test_kev_classifier.py              # canonical edge cases only (fast)
    python tests/test_kev_classifier.py --full       # re-classify pinned snapshot, compare
                                                     # to data/kev-layer-classifications.json

Exit 0 if all checks pass, 1 on the first failure (fail-loud).

When to add cases here:
    * Any time the classifier rules change.
    * Any time a new KEV entry surfaces an edge case the current cases don't cover.
    * If the doc adds a new claim that depends on a layer boundary (e.g. "Cisco Webex
      is JVM, not VPN") → add the canonical case so the claim is tested.

If a case here starts failing:
    * The classifier's rule order or coverage changed. Verify the new behavior is
      intentional, then update the case. Don't just delete it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

# data/kev-classifier.py has a hyphen in the filename so we can't regular-import it.
# Load it explicitly via importlib.
def _load_classifier():
    path = REPO / "data" / "kev-classifier.py"
    spec = importlib.util.spec_from_file_location("kev_classifier", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod

classify = _load_classifier().classify


# --------------------------------------------------------------------------- #
# Canonical cases.  Each tuple is (vendorProject, product, expected_layer).
# vulnerabilityName and shortDescription are left empty; the classifier must
# resolve the layer from vendor + product alone for all of these.
# --------------------------------------------------------------------------- #
CASES: list[tuple[str, str, str]] = [
    # ---- Browser (and Apple browser products that must NOT fall into OS) ----
    ("Google", "Chrome", "browser"),
    ("Google", "Chromium", "browser"),
    ("Mozilla", "Firefox", "browser"),
    ("Microsoft", "Internet Explorer", "browser"),
    ("Microsoft", "Edge", "browser"),
    ("Apple", "Safari", "browser"),
    ("Apple", "WebKit", "browser"),
    ("Adobe", "Flash Player", "browser"),

    # ---- Email / collab server (must run before Microsoft→OS) ----
    ("Microsoft", "Exchange Server", "email_collab_server"),
    ("Microsoft", "SharePoint", "email_collab_server"),
    ("Microsoft", "SharePoint Server", "email_collab_server"),
    ("Synacor", "Zimbra Collaboration Suite (ZCS)", "email_collab_server"),
    ("Roundcube", "Webmail", "email_collab_server"),
    ("Barracuda Networks", "Email Security Gateway (ESG) Appliance", "email_collab_server"),

    # ---- Virtualization / container ----
    ("VMware", "ESXi", "virtualization_container"),
    ("VMware", "vCenter Server", "virtualization_container"),

    # ---- Database ----
    ("Microsoft", "SQL Server", "database"),
    ("Oracle", "Database Server", "database"),

    # ---- CMS / webapp ----
    ("WordPress Foundation", "WordPress", "cms_webapp"),
    ("Drupal", "Drupal Core", "cms_webapp"),
    ("Craft CMS", "Craft CMS", "cms_webapp"),
    ("Sitecore", "Sitecore CMS", "cms_webapp"),

    # ---- Web server (narrow — NOT Tomcat/Struts/Spring) ----
    ("Apache", "HTTP Server", "web_server"),
    ("Apache", "Tomcat", "jvm_runtime"),         # explicitly NOT web_server
    ("Apache", "Struts", "jvm_runtime"),          # explicitly NOT library_framework

    # ---- SSL / TLS / crypto libraries ----
    ("OpenSSL", "OpenSSL", "ssl_tls_crypto"),
    ("wolfSSL", "wolfSSL", "ssl_tls_crypto"),
    ("Bouncy Castle", "Bouncy Castle", "ssl_tls_crypto"),

    # ---- Firmware / hardware / silicon ----
    ("Qualcomm", "Multiple Chipsets", "firmware_hardware"),
    ("Arm", "Mali Graphics Processing Unit (GPU)", "firmware_hardware"),

    # ---- Productivity desktop (Adobe Acrobat/Reader NOT browser, NOT OS) ----
    ("Microsoft", "Office", "productivity_desktop"),
    ("Microsoft", "Excel", "productivity_desktop"),
    ("Adobe", "Acrobat", "productivity_desktop"),
    ("Adobe", "Acrobat Reader", "productivity_desktop"),
    ("Adobe", "ColdFusion", "jvm_runtime"),      # Adobe but NOT productivity

    # ---- Cisco tricky cases ----
    ("Cisco", "Adaptive Security Appliance (ASA) and Firepower Threat Defense (FTD) Software", "vpn_network_appliance"),
    ("Cisco", "IOS XE", "vpn_network_appliance"),
    ("Cisco", "Webex Player", "jvm_runtime"),
    ("Cisco", "Identity Services Engine (ISE)", "jvm_runtime"),

    # ---- VPN / network appliance ----
    ("Fortinet", "FortiOS", "vpn_network_appliance"),
    ("Palo Alto Networks", "PAN-OS", "vpn_network_appliance"),
    ("SonicWall", "SonicOS", "vpn_network_appliance"),
    ("Ivanti", "Connect Secure", "vpn_network_appliance"),
    ("Citrix", "ADC", "vpn_network_appliance"),
    ("Citrix", "NetScaler ADC", "vpn_network_appliance"),
    ("F5", "BIG-IP", "vpn_network_appliance"),
    ("Check Point", "Quantum Security Gateway", "vpn_network_appliance"),
    ("Juniper", "Junos OS", "vpn_network_appliance"),

    # ---- JVM / runtime platform ----
    ("Atlassian", "Confluence Server", "jvm_runtime"),
    ("Atlassian", "Jira Server", "jvm_runtime"),
    ("Jenkins", "Jenkins", "jvm_runtime"),

    # ---- Library / framework (narrow) ----
    ("Apache", "Log4j2", "library_framework"),
    ("XStream", "XStream", "library_framework"),
    ("Cacti", "Cacti", "library_framework"),

    # ---- IoT / ICS / SMB NAS / consumer router ----
    ("Siemens", "SIMATIC", "iot_ics"),
    ("QNAP", "QTS", "iot_ics"),
    ("D-Link", "DIR-825", "iot_ics"),
    ("TP-Link", "Archer AX21", "iot_ics"),

    # ---- Broad OS (after all earlier rules) ----
    ("Microsoft", "Windows", "os"),
    ("Microsoft", "Win32k", "os"),
    ("Microsoft", ".NET Framework", "os"),
    ("Apple", "iOS and iPadOS", "os"),
    ("Apple", "macOS", "os"),
    ("Google", "Android", "os"),
    ("Android", "Framework", "os"),    # KEV records some as vendor=Android
    ("Android", "Pixel", "os"),
    ("Android", "Kernel", "os"),
    ("Samsung", "Mobile Devices", "os"),
    ("Linux", "Kernel", "os"),
]


def _run_cases() -> int:
    failures = 0
    for vendor, product, expected in CASES:
        entry = {
            "vendorProject": vendor,
            "product": product,
            "vulnerabilityName": "",
            "shortDescription": "",
        }
        actual = classify(entry)
        if actual != expected:
            failures += 1
            print(f"FAIL  {vendor!r} / {product!r}")
            print(f"      expected layer: {expected}")
            print(f"      actual   layer: {actual}")
    total = len(CASES)
    ok = total - failures
    print(f"\n[canonical] {ok}/{total} passed" + (" — all green" if not failures else f" — {failures} FAILED"))
    return 1 if failures else 0


def _run_full() -> int:
    """Re-classify the pinned snapshot; expect exact match with stored classifications."""
    snap = json.load(open(REPO / "data" / "kev-snapshot-2026-04-23.json"))
    stored = json.load(open(REPO / "data" / "kev-layer-classifications.json"))
    stored_by_cve = {r["cveID"]: r["layer"] for r in stored["classifications"]}

    failures = 0
    for entry in snap["vulnerabilities"]:
        cve = entry["cveID"]
        expected = stored_by_cve.get(cve)
        if expected is None:
            failures += 1
            print(f"FAIL  {cve} not in stored classifications")
            continue
        actual = classify(entry)
        if actual != expected:
            failures += 1
            print(f"FAIL  {cve} ({entry.get('vendorProject')}/{entry.get('product')})")
            print(f"      stored: {expected}   classifier now: {actual}")
    total = len(snap["vulnerabilities"])
    ok = total - failures
    print(f"\n[full] {ok}/{total} entries match stored classifications"
          + (" — reproducible" if not failures else f" — {failures} DRIFTED"))
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--full", action="store_true",
                    help="Also re-classify the pinned snapshot end-to-end.")
    args = ap.parse_args()

    rc = _run_cases()
    if args.full:
        rc = _run_full() or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
