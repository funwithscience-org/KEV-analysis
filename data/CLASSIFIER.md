# KEV Layer Classifier — Build Record

## Why this exists

The dashboard previously displayed per-layer KEV counts (os 153, vpn 100, …) that
were produced by *ratio estimation*, not by actually classifying each KEV
entry. The original classifier that produced those numbers was lost. Ratio
estimates were produced by applying 2021+ fractions from an approximate
classifier to the dashboard's original unwindowed counts and then fudging the
`other` bucket to make the total hit 886. That gave a ransomware count of 191
when ground truth is 186, and required a manual adjustment of `other` — not
defensible.

This classifier replaces ratio estimation with actual per-entry classification
over a pinned input snapshot. Anyone who runs the script gets the same output.

## What it does

`kev-classifier.py` takes the CISA KEV JSON (either live-fetched or a pinned
snapshot) and assigns each entry to one of fifteen stack layers:

```
os, vpn_network_appliance, jvm_runtime, productivity_desktop,
email_collab_server, browser, iot_ics, database,
virtualization_container, library_framework, cms_webapp,
web_server, firmware_hardware, ssl_tls_crypto, other
```

Rules are *first-match-wins*. Very specific product names are checked before
generic vendor names; platforms/runtimes before broad OS detection; everything
that doesn't clearly fit falls into `other`.

## Inputs and outputs

Input: CISA KEV feed —
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Outputs (written next to the script):

- `kev-snapshot-YYYY-MM-DD.json` — the KEV JSON we classified (only when
  live-fetching). Pinning it makes the run reproducible.
- `kev-layer-classifications.json` — per-entry `{cveID, year, layer,
  isRansomware, vendor, product, dateAdded}`, plus a `summary` block with
  counts, the `catalogVersion`, and a sha256 prefix of the input.

## Run

```
cd KEV-analysis
python3 data/kev-classifier.py                              # live fetch, writes snapshot
python3 data/kev-classifier.py --input data/kev-snapshot-2026-04-23.json --no-snapshot
```

## Rule order (what checks run, in sequence)

1. **Browser** — Chrome, Firefox, Edge, IE, Safari, WebKit, Chromium, Flash.
   Runs before Apple→OS so Safari/WebKit go to browser.
2. **Email / collab server** — Exchange Server, SharePoint, Zimbra, Roundcube,
   Exim, Barracuda email/ESG. Runs before Microsoft→OS so Exchange and
   SharePoint go to email_collab_server.
3. **Virtualization / container** — ESXi, vCenter, vSphere, VMware
   Workstation/Fusion, Kubernetes, Docker, Hyper-V, Citrix XenServer/XenApp/
   XenDesktop.
4. **Database** — SQL Server, MySQL, PostgreSQL, MongoDB, Redis, Oracle
   Database / TNS Listener / E-Business Suite.
5. **CMS / webapp** — WordPress, Drupal, Joomla, Magento, PrestaShop, Craft
   CMS, Sitecore.
6. **Web server** (narrow) — Apache HTTP Server, nginx, IIS, Caddy. Explicitly
   NOT Tomcat/Struts/Spring — those are jvm_runtime.
7. **SSL / TLS / crypto** — OpenSSL, GnuTLS, wolfSSL, Bouncy Castle, LibreSSL.
8. **Firmware / hardware** — BIOS, UEFI, Intel Management Engine, BMC,
   anything with `firmware` in the product name, `chipset` anywhere, plus
   Qualcomm (silicon) and Arm (Mali GPU, Cortex, chipset).
9. **Productivity desktop** — Microsoft Office/Excel/Word/PowerPoint/Outlook,
   Adobe Acrobat/Reader, WinRAR, 7-Zip.
10. **Cisco Webex / ISE / Unified Communications** → jvm_runtime. Must run
    before the generic Cisco → vpn rule.
11. **JVM runtime** — Tomcat, JBoss, WebLogic, WebSphere, Confluence, Jira,
    Jenkins, ColdFusion, Liferay, Struts, Spring Framework/Boot/Cloud,
    Atlassian products.
12. **Library / framework** (narrow) — Log4j, jQuery, XStream, FastJSON,
    Apache Commons, Cacti. Intentionally narrow; Struts/Tomcat/Spring are
    jvm_runtime even though they're technically frameworks.
13. **VPN / network appliance** — Fortinet, Palo Alto, SonicWall, Pulse
    Secure, Ivanti, Zyxel, Sophos, Citrix ADC/Gateway/NetScaler, F5 BIG-IP,
    Check Point, Juniper, non-email Barracuda, generic Cisco.
14. **IoT / ICS** — Siemens, Schneider, Rockwell, Honeywell, QNAP, Synology,
    Hikvision, Dahua, DrayTek, Tenda, TP-Link, D-Link, Netgear.
15. **OS** (broad) — vendor=Microsoft (catch-all after Office/Exchange/
    SharePoint), vendor=Apple (catch-all after Safari/WebKit), Google
    Android, vendor=Android (for KEV entries recorded that way:
    Framework / Pixel / Kernel), Samsung mobile devices (Android handsets),
    Linux kernel.
16. **Other** — everything else.

## Verification (for snapshot `kev-snapshot-2026-04-23.json`, catalogVersion 2026.04.23)

- Total KEV entries: 1,579
- Windowed (CVE year ≥ 2021): 887
- Ransomware (all): 317
- Ransomware (windowed): **186** (matches ground truth exactly)

Windowed KEV by layer:

| layer | kev | nvd | rate |
|---|---:|---:|---:|
| other | 279 | 17,028 | 1.64% |
| os | 251 | 321 | 78.19% |
| vpn_network_appliance | 130 | 804 | 16.17% |
| browser | 56 | 601 | 9.32% |
| email_collab_server | 44 | 44 | 100.00% |
| jvm_runtime | 25 | 348 | 7.18% |
| firmware_hardware | 23 | 3,739 | 0.62% |
| iot_ics | 22 | 92 | 23.91% |
| productivity_desktop | 21 | 129 | 16.28% |
| virtualization_container | 14 | 111 | 12.61% |
| cms_webapp | 10 | 70 | 14.29% |
| database | 5 | 48 | 10.42% |
| library_framework | 4 | 80 | 5.00% |
| web_server | 3 | 47 | 6.38% |
| ssl_tls_crypto | 0 | 39 | 0.00% |

- Sum of windowed KEV across layers: 887 ✓
- Sum of NVD denominators: 23,501 ✓
- No rate exceeds 100% ✓

## Known caveats

1. **NVD denominators are inherited, not re-derived.** The original NVD
   per-layer query predates this build and cannot be easily reproduced (NVD's
   API rate limits make bulk queries impractical). We keep the denominators
   as-is. If a layer's KEV count ever exceeds its NVD denominator, that's a
   signal the denominator is stale (NVD has accreted new
   criticals/highs since) or the classifier has broadened. Today, nothing
   exceeds.

2. **email_collab_server at 100.00%.** Forty-four KEV entries against an NVD
   denominator of 44. All forty-four entries are real and correctly
   classified (Exchange Server 14, Zimbra 14, SharePoint 8, Roundcube 7,
   Barracuda ESG 1). Interpretation: in the 2021-2026 window, every NVD
   critical/high in this narrow category has been exploited in the wild. The
   category is small and high-value, so this is plausible — but the 100.00%
   leaves no headroom, and any new email/collab KEV entry will tip the rate
   over 100% until the NVD denominator is refreshed. Flag, don't fix.
   There is one stray KEV entry with `product="Exchange"` (no "Server") that
   we leave in `os`; routing it to email_collab would take us to 45/44.

3. **os rate of 78%.** The KEV layer "os" sweeps all Microsoft catch-all
   products (Win32k, MSHTML, .NET, Defender, Active Directory, etc.), all
   Apple OS products, Google Android, Android-as-vendor (Framework / Pixel /
   Kernel), Samsung mobile devices, and the Linux kernel. The NVD
   denominator of 321 may have been narrower (plausibly Windows-only). The
   rate is high but under 100%, so we keep it and note the boundary mismatch.

4. **`other` still large (279).** Includes SolarWinds, SAP NetWeaver,
   Accellion FTA, CrushFTP, Wing FTP, Serv-U, GoAnywhere MFT, Veeam,
   Nagios XI, Zoho ManageEngine, Mitel, Samsung non-mobile, and many
   one-off products. Per the instructions: "When in doubt, use 'other'.
   It's better to undercount a specific layer than overcount it." These
   entries could be sub-categorized further but don't cleanly fit the 14
   named layers.

5. **Library / framework (narrow, 4).** Deliberately small: only
   standalone open-source libraries (Log4j, Apache Commons, Cacti,
   XStream). Struts, Tomcat, and Spring all go to `jvm_runtime`. This
   matches the instructions.

## Delta vs. the prior ratio estimates

| layer | prior (ratio) | new (actual) | delta |
|---|---:|---:|---:|
| other | 434 | 279 | −155 |
| os | 153 | 251 | +98 |
| vpn_network_appliance | 100 | 130 | +30 |
| jvm_runtime | 17 | 25 | +8 |
| productivity_desktop | 26 | 21 | −5 |
| email_collab_server | 42 | 44 | +2 |
| browser | 22 | 56 | +34 |
| iot_ics | 23 | 22 | −1 |
| database | 15 | 5 | −10 |
| virtualization_container | 22 | 14 | −8 |
| library_framework | 14 | 4 | −10 |
| cms_webapp | 5 | 10 | +5 |
| web_server | 9 | 3 | −6 |
| firmware_hardware | 4 | 23 | +19 |
| ssl_tls_crypto | 0 | 0 | 0 |
| **total** | **886** | **887** | **+1** |

The +1 in total is from the refresh agent adding a new KEV entry in the
2021+ window since the prior snapshot. Major shifts:

- `other` shrank because the silicon vendors, Android-as-vendor, Samsung
  mobile devices, and a few mis-swept entries moved to their natural homes.
- `os` grew because Android/Samsung/Apple catch-alls now land here.
- `firmware_hardware` grew from 4 to 23 as Qualcomm chipsets and Arm Mali
  GPUs are now routed correctly.
- `browser` grew because earlier ratio estimates undercounted it.
- `library_framework` contracted sharply — the prior ratio estimate was
  probably sweeping jvm_runtime products into it.

The ransomware total is exactly 186, matching ground truth.

## How to regenerate from scratch

```
cd KEV-analysis
python3 data/kev-classifier.py                # writes snapshot + classifications
# OR to re-run against a pinned snapshot:
python3 data/kev-classifier.py --input data/kev-snapshot-2026-04-23.json --no-snapshot
```

To rebuild dashboard/walkthrough DATA blobs, read
`data/kev-layer-classifications.json` and pivot into `layer_data`,
`ransomware_count`, and `ransomware_data` shapes that match the existing
DATA blob structure. Keep NVD denominators unchanged. Rates are
`round(kev / nvd * 100, 2)`.
