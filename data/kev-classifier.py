#!/usr/bin/env python3
"""
KEV layer classifier.

Maps each CISA KEV entry to one of fifteen stack layers by inspecting
its vendorProject / product / vulnerabilityName / shortDescription fields.

Rules follow CLASSIFIER-BUILD-INSTRUCTIONS.md. Execution order matters:
specific products are checked first, then platforms/runtimes, then vendors,
then broad OS detection, then 'other' as the default. First match wins.

Usage:
    python data/kev-classifier.py                           # live fetch
    python data/kev-classifier.py --input data/kev-snapshot.json

Outputs (relative to repo root):
    data/kev-snapshot-YYYY-MM-DD.json        # snapshot of input (if live-fetched)
    data/kev-layer-classifications.json      # per-entry classification list
    prints verification summary to stdout
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.request
from collections import Counter
from typing import Any

LAYERS = (
    "os",
    "vpn_network_appliance",
    "jvm_runtime",
    "productivity_desktop",
    "email_collab_server",
    "browser",
    "iot_ics",
    "database",
    "virtualization_container",
    "library_framework",
    "cms_webapp",
    "web_server",
    "firmware_hardware",
    "ssl_tls_crypto",
    "other",
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


# --------------------------------------------------------------------------- #
# The classifier
# --------------------------------------------------------------------------- #
def classify(entry: dict[str, Any]) -> str:
    """Return one of LAYERS for a single KEV entry. First match wins."""
    v = (entry.get("vendorProject") or "").lower()
    p = (entry.get("product") or "").lower()
    n = (entry.get("vulnerabilityName") or "").lower()
    d = (entry.get("shortDescription") or "").lower()
    vp = f"{v} {p}"
    all_text = f"{v} {p} {n} {d}"

    def has(*needles: str) -> bool:
        """True if any needle is a substring of vendor+product."""
        return any(needle in vp for needle in needles)

    # ------------------------------------------------------------------ #
    # Tier 1 — very specific products
    # ------------------------------------------------------------------ #

    # Browser (incl. Adobe Flash; must run before Adobe → productivity,
    # and before Apple → OS to catch Safari/WebKit)
    if has(
        "chrome",
        "chromium",
        "firefox",
        "mozilla",
        "internet explorer",
        "microsoft edge",
        "safari",
        "webkit",
        "adobe flash",
        "flash player",
    ):
        return "browser"

    # Email / collab server (must run before Microsoft → OS)
    if has("exchange server", "sharepoint", "zimbra", "roundcube", "exim"):
        return "email_collab_server"
    # Barracuda ESG / email products
    if "barracuda" in v and (
        "email" in p or "esg" in p or "spam" in p or "message archiver" in p
    ):
        return "email_collab_server"

    # Virtualization / container
    if has(
        "esxi",
        "vcenter",
        "vsphere",
        "vmware workstation",
        "vmware fusion",
        "kubernetes",
        "docker",
        "hyper-v",
    ):
        return "virtualization_container"
    if "citrix" in v and ("xenserver" in p or "xenapp" in p or "xendesktop" in p):
        return "virtualization_container"

    # Database
    if has(
        "sql server",
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
    ):
        return "database"
    # Oracle Database (product strings in KEV typically "Database Server")
    if "oracle" in v and (
        "database" in p or "tns listener" in p or "e-business suite" in p
    ):
        # keep e-business suite → database as a best-guess; it is tightly coupled
        # to the Oracle DB stack. Could also be 'other'; calling it db keeps
        # these in one bucket rather than leaking into 'other'.
        return "database"

    # CMS / webapp
    if has(
        "wordpress",
        "drupal",
        "joomla",
        "magento",
        "prestashop",
        "craft cms",
        "sitecore",
        "roundcube",  # also caught above; harmless
    ):
        return "cms_webapp"

    # Web server (narrow — Apache HTTP, nginx, IIS, Caddy; NOT Struts/Tomcat)
    if has("apache http server", "httpd"):
        return "web_server"
    if v == "nginx" or "nginx" in p:
        return "web_server"
    if (
        "internet information services" in vp
        or " iis " in f" {vp} "
        or vp.endswith(" iis")
        or vp.startswith("iis ")
    ):
        return "web_server"
    if v == "caddy" or p == "caddy":
        return "web_server"

    # SSL / TLS / crypto library
    if has("openssl", "gnutls", "wolfssl", "bouncy castle", "bouncycastle", "libressl"):
        return "ssl_tls_crypto"

    # Firmware / hardware
    if has(
        "bios",
        "uefi",
        "intel management engine",
        "baseboard management controller",
        "bmc",
        "chipset",
    ):
        return "firmware_hardware"
    # Printer firmware — only when the word "firmware" is in product name
    if "firmware" in p:
        return "firmware_hardware"
    # Silicon vendors: Qualcomm, Arm (Mali GPU / Cortex)
    if v == "qualcomm" or "qualcomm" in v:
        return "firmware_hardware"
    if v == "arm" and ("mali" in p or "gpu" in p or "cortex" in p or "chipset" in p):
        return "firmware_hardware"

    # Productivity desktop (MS Office, Adobe Acrobat/Reader, archivers)
    if has(
        "microsoft office",
        "office excel",
        "office word",
        "office powerpoint",
        "office outlook",
        "excel",
        "word",
        "powerpoint",
        "outlook",
    ):
        return "productivity_desktop"
    if "adobe" in v and ("acrobat" in p or "reader" in p):
        return "productivity_desktop"
    if has("winrar", "7-zip", "7zip"):
        return "productivity_desktop"

    # ------------------------------------------------------------------ #
    # Tier 2 — platform/runtime
    # ------------------------------------------------------------------ #

    # Cisco Webex / ISE (must run before generic Cisco → vpn)
    if "cisco" in v and (
        "webex" in p
        or " ise" in f" {p} "
        or "identity services engine" in p
        or "unified communications" in p
        or "unified call" in p
    ):
        return "jvm_runtime"

    # JVM runtime (Tomcat, JBoss, WebLogic, WebSphere, Confluence, Jira,
    # Jenkins, ColdFusion, Liferay, Struts, Spring, Atlassian)
    if has(
        "tomcat",
        "jboss",
        "weblogic",
        "websphere",
        "confluence",
        " jira",
        "jira ",
        "jira\t",
        "jenkins",
        "coldfusion",
        "liferay",
        "struts",
        "spring framework",
        "spring boot",
        "spring cloud",
    ):
        return "jvm_runtime"
    if p == "jira" or v == "atlassian":
        return "jvm_runtime"

    # Library / framework (narrow — standalone OSS libs only)
    if has("log4j", "jquery", "xstream", "fastjson"):
        return "library_framework"
    if "apache" in v and ("commons" in p):
        return "library_framework"
    if v == "cacti" or p == "cacti":
        return "library_framework"

    # ------------------------------------------------------------------ #
    # Tier 3 — vendor-based (network appliances, IoT)
    # ------------------------------------------------------------------ #

    # VPN / network appliance
    if "fortinet" in v or "fortios" in p or "fortigate" in p or "fortimanager" in p or "fortianalyzer" in p:
        return "vpn_network_appliance"
    if "palo alto" in v or "pan-os" in p:
        return "vpn_network_appliance"
    if "sonicwall" in v:
        return "vpn_network_appliance"
    if "pulse secure" in v or "pulse secure" in p or "pulse connect" in p:
        return "vpn_network_appliance"
    if "ivanti" in v:
        # Connect Secure, Policy Secure, Neurons, Sentry, Endpoint Manager → all appliance-shaped
        return "vpn_network_appliance"
    if "zyxel" in v:
        return "vpn_network_appliance"
    if "sophos" in v:
        return "vpn_network_appliance"
    if "citrix" in v and ("adc" in p or "gateway" in p or "netscaler" in p):
        return "vpn_network_appliance"
    if "f5" in v and ("big-ip" in p or "bigip" in p):
        return "vpn_network_appliance"
    if "check point" in v or "checkpoint" in v:
        return "vpn_network_appliance"
    if "juniper" in v:
        return "vpn_network_appliance"
    if "barracuda" in v:
        # non-email barracuda (e.g., Load Balancer, Web Filter)
        return "vpn_network_appliance"
    # Cisco catch-all (after Webex/ISE special case above)
    if "cisco" in v:
        return "vpn_network_appliance"

    # IoT / ICS / SMB NAS / consumer router
    if has(
        "siemens",
        "schneider",
        "rockwell",
        "honeywell",
        "qnap",
        "synology",
        "hikvision",
        "dahua",
        "draytek",
        "tenda",
        "tp-link",
        "d-link",
        "netgear",
    ):
        return "iot_ics"

    # ------------------------------------------------------------------ #
    # Tier 4 — broad OS
    # ------------------------------------------------------------------ #
    if "microsoft" in v:
        # Windows, Win32k, NTFS, CLFS, MSHTML, .NET, ASP.NET, etc. fall here.
        # (Office/SharePoint/Exchange already handled above.)
        return "os"
    if "apple" in v:
        # macOS, iOS, iPadOS, tvOS, watchOS. (Safari/WebKit already handled.)
        return "os"
    if "google" in v and "android" in p:
        return "os"
    # Android vendor (KEV also records some entries with vendor="Android" directly:
    # Framework, Pixel, Kernel). These are Android-OS issues.
    if v == "android":
        return "os"
    # Samsung mobile devices — Android-based handsets. Product strings like
    # "Mobile Devices" or explicit Galaxy references. Narrow match to avoid
    # sweeping Samsung's non-mobile products.
    if "samsung" in v and ("mobile" in p or "galaxy" in p):
        return "os"
    if v == "linux" or "linux kernel" in p or "linux kernel" in n:
        return "os"

    # ------------------------------------------------------------------ #
    # Default
    # ------------------------------------------------------------------ #
    return "other"


# --------------------------------------------------------------------------- #
# Run + save
# --------------------------------------------------------------------------- #
def year_of(cve_id: str) -> int | None:
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None


def fetch_kev() -> dict[str, Any]:
    """Live-fetch the CISA KEV feed."""
    with urllib.request.urlopen(KEV_URL, timeout=30) as r:
        return json.loads(r.read())


def load_kev(path: str) -> dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def classify_all(kev: dict[str, Any]) -> list[dict[str, Any]]:
    vulns = kev["vulnerabilities"]
    out = []
    for e in vulns:
        cve = e.get("cveID", "")
        year = year_of(cve)
        layer = classify(e)
        out.append(
            {
                "cveID": cve,
                "year": year,
                "layer": layer,
                "isRansomware": e.get("knownRansomwareCampaignUse") == "Known",
                "vendor": e.get("vendorProject", ""),
                "product": e.get("product", ""),
                "dateAdded": e.get("dateAdded", ""),
            }
        )
    return out


def summarize(classifications: list[dict[str, Any]]) -> dict[str, Any]:
    windowed = [r for r in classifications if r["year"] and r["year"] >= 2021]
    ransom_all = [r for r in classifications if r["isRansomware"]]
    ransom_win = [r for r in windowed if r["isRansomware"]]

    layer_counts = Counter(r["layer"] for r in windowed)
    ransom_layer_counts = Counter(r["layer"] for r in ransom_win)

    return {
        "total_kev": len(classifications),
        "windowed_kev": len(windowed),
        "ransomware_total": len(ransom_all),
        "ransomware_windowed": len(ransom_win),
        "layer_counts_windowed": dict(layer_counts),
        "ransomware_layer_counts_windowed": dict(ransom_layer_counts),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--input",
        help="Path to a pinned KEV JSON snapshot (skip live fetch).",
    )
    ap.add_argument(
        "--outdir",
        default=os.path.join(os.path.dirname(__file__) or ".", ""),
        help="Directory for output files (default: this script's directory).",
    )
    ap.add_argument(
        "--no-snapshot",
        action="store_true",
        help="Do not save a snapshot of the input JSON (use when reading a pinned snapshot).",
    )
    args = ap.parse_args()

    # Resolve outdir to repo-root-relative path.
    outdir = args.outdir or os.path.dirname(os.path.abspath(__file__))
    os.makedirs(outdir, exist_ok=True)

    if args.input:
        kev = load_kev(args.input)
        source = f"pinned:{os.path.abspath(args.input)}"
    else:
        kev = fetch_kev()
        source = f"live:{KEV_URL}"

    raw_bytes = json.dumps(kev, sort_keys=True).encode()
    sha = hashlib.sha256(raw_bytes).hexdigest()[:16]

    if not args.input and not args.no_snapshot:
        today = dt.date.today().isoformat()
        snap_path = os.path.join(outdir, f"kev-snapshot-{today}.json")
        with open(snap_path, "w") as f:
            json.dump(kev, f, indent=2)
        print(f"[snapshot] wrote {snap_path} ({sha=})")

    classifications = classify_all(kev)
    summary = summarize(classifications)

    out_path = os.path.join(outdir, "kev-layer-classifications.json")
    with open(out_path, "w") as f:
        json.dump(
            {
                "generated_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "source": source,
                "input_sha256_16": sha,
                "kev_catalog_version": kev.get("catalogVersion"),
                "kev_date_released": kev.get("dateReleased"),
                "summary": summary,
                "classifications": classifications,
            },
            f,
            indent=2,
        )
    print(f"[classify] wrote {out_path}")

    print()
    print("=" * 60)
    print(f"Source:                 {source}")
    print(f"Catalog version:        {kev.get('catalogVersion')}")
    print(f"Total KEV entries:      {summary['total_kev']}")
    print(f"Windowed (CVE ≥ 2021):  {summary['windowed_kev']}")
    print(f"Ransomware (all):       {summary['ransomware_total']}")
    print(f"Ransomware (windowed):  {summary['ransomware_windowed']}")
    print("-" * 60)
    print("Windowed KEV by layer:")
    for layer in LAYERS:
        print(f"  {layer:30s} {summary['layer_counts_windowed'].get(layer, 0):5d}")
    print("-" * 60)
    print("Windowed ransomware KEV by layer:")
    for layer in LAYERS:
        n = summary["ransomware_layer_counts_windowed"].get(layer, 0)
        if n:
            print(f"  {layer:30s} {n:5d}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
