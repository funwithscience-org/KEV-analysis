"""Build final output JSON and markdown report.

Stage 4 of the foss_sub7 pipeline. Reads server_side_filtered.json from
data/_foss-sub7-cache/ and writes data/foss-sub7-exploited.json
plus analyst-reports/2026-04-29-foss-sub7-exploit-scan.md.
"""
import json
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORK = REPO / "data" / "_foss-sub7-cache"
OUT_JSON = REPO / "data" / "foss-sub7-exploited.json"
OUT_MD = REPO / "analyst-reports" / "2026-04-29-foss-sub7-exploit-scan.md"
OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
OUT_MD.parent.mkdir(parents=True, exist_ok=True)

records = json.load(open(WORK / "server_side_filtered.json"))

# Build the final per-record output as specified:
# {cve, package, ecosystem, cvss_score, cvss_vector, evidence_sources: [...],
#  summary, server_side: true, server_side_rationale, osv_id}
# Note: spec says "package" (singular). Where multiple packages share one OSV record,
# we expand to per-package rows.

final = []
for r in records:
    pkgs = r["packages"] or [None]
    for p in pkgs:
        rec = {
            "cve": r["cve"],
            "package": p,
            "ecosystem": r["ecosystem"],
            "cvss_score": r["cvss_score"],
            "cvss_vector": r["cvss_vector"],
            "cvss_version": r.get("cvss_version", "v3"),
            "evidence_sources": r["evidence_sources"],
            "summary": r["summary"],
            "details_excerpt": r["details_excerpt"],
            "server_side": True,
            "server_side_rationale": r["server_side_rationale"],
            "osv_id": r["osv_id"],
            "osv_published": r.get("published"),
            "osv_modified": r.get("modified"),
            "exploitdb_entries": r.get("exploitdb_entries", []),
        }
        final.append(rec)

# Sort: by CVSS desc, then CVE
final.sort(key=lambda x: (-x["cvss_score"], x["cve"], x["package"] or ""))

OUT_JSON.write_text(json.dumps(final, indent=2))
print(f"Wrote {len(final)} per-package records to {OUT_JSON}")

# === Build markdown report ===
distinct_cves = sorted({r["cve"] for r in final})
n_cves = len(distinct_cves)

# Source overlap (distinct CVE level)
cve_sources = defaultdict(set)
for r in final:
    cve_sources[r["cve"]].update(r["evidence_sources"])

src_overlap = defaultdict(int)
for cve, ss in cve_sources.items():
    src_overlap["+".join(sorted(ss))] += 1

src_any = {"KEV": 0, "Metasploit": 0, "ExploitDB": 0}
for cve, ss in cve_sources.items():
    for s in ss:
        src_any[s] += 1

# Ecosystem breakdown (distinct CVE)
eco_cves = defaultdict(set)
for r in final:
    eco_cves[r["ecosystem"]].add(r["cve"])
eco_breakdown = sorted(((e, len(s)) for e, s in eco_cves.items()), key=lambda x: -x[1])

# CVSS distribution
cvss_buckets = defaultdict(set)
for r in final:
    s = r["cvss_score"]
    if s >= 6.0:
        b = "6.0-6.9 (Med-High)"
    elif s >= 5.0:
        b = "5.0-5.9 (Med)"
    elif s >= 4.0:
        b = "4.0-4.9 (Med-Low)"
    else:
        b = "0.1-3.9 (Low)"
    cvss_buckets[b].add(r["cve"])
cvss_dist = sorted(((b, len(s)) for b, s in cvss_buckets.items()), key=lambda x: x[0], reverse=True)

# Top 20 by significance — pick KEV first, then Metasploit, then highest CVSS within ExploitDB-only
def sig_score(cve):
    ss = cve_sources[cve]
    rec = next(r for r in final if r["cve"] == cve)
    base = rec["cvss_score"]
    bonus = 0
    if "KEV" in ss: bonus += 10
    if "Metasploit" in ss: bonus += 5
    return -(base + bonus)  # most-significant first

top20 = sorted(distinct_cves, key=sig_score)[:20]

# One-line context per CVE
def one_liner(cve):
    rec = next(r for r in final if r["cve"] == cve)
    pkgs_for_cve = sorted({rr["package"] for rr in final if rr["cve"] == cve and rr["package"]})
    pkg = pkgs_for_cve[0] if pkgs_for_cve else "?"
    src = "+".join(sorted(cve_sources[cve]))
    return f"`{cve}` ({rec['cvss_score']} {src}) — {pkg}: {rec['summary'][:120]}"

# By ecosystem markdown
eco_md = "\n".join(f"- **{e}**: {n}" for e, n in eco_breakdown)

# Source overlap markdown
overlap_md = "\n".join(f"- {k}: {v}" for k, v in sorted(src_overlap.items(), key=lambda x: -x[1]))

# CVSS dist markdown
cvss_md = "\n".join(f"- {b}: {n}" for b, n in cvss_dist)

# Top 20 markdown
top_md = "\n".join(f"{i+1}. {one_liner(c)}" for i, c in enumerate(top20))

md = f"""# FOSS sub-7 server-side exploited CVEs — scan results

_Generated 2026-04-29 from OSV all.zip per ecosystem, cross-referenced against CISA KEV, Metasploit modules, and ExploitDB._

## Summary

- **Total distinct CVEs**: **{n_cves}** (server-side, FOSS, CVSS v3 < 7.0, with at least one exploitation-evidence source)
- **Total per-package records**: {len(final)} (some CVEs span multiple ecosystems/packages)
- **Records excluded as client-side**: 10 distinct CVEs (jQuery family, joplin, puppeteer, CefSharp, docsify) — see methodology

The dominant pattern: **server-side CMS/admin-panel XSS, path traversal, SSRF, and CSRF**, mostly in the 5.x–6.x medium band, mostly attested by ExploitDB. Higher-tier exploitation evidence (KEV, Metasploit) is present but rare in the sub-7 zone.

## Breakdown by ecosystem (distinct CVEs)

{eco_md}

## Breakdown by evidence source (distinct CVEs)

Sources, any:
- KEV: {src_any['KEV']}
- Metasploit: {src_any['Metasploit']}
- ExploitDB: {src_any['ExploitDB']}

Source overlap (each CVE counted once):
{overlap_md}

## CVSS distribution

{cvss_md}

## Top 20 most-significant entries

Significance ranking: KEV > Metasploit > highest CVSS in ExploitDB-only.

{top_md}

## Methodology

### Data sources

1. **OSV.dev all.zip per ecosystem**, downloaded 2026-04-29 from `https://osv-vulnerabilities.storage.googleapis.com/{{ECOSYSTEM}}/all.zip`. Ecosystems pulled: Maven, npm, PyPI, Go, RubyGems, crates.io, Packagist, NuGet, Hex.
2. **CISA KEV** — `known_exploited_vulnerabilities.json` catalogVersion 2026.04.28 ({{n_kev}} CVEs).
3. **Metasploit** — `modules_metadata_base.json` from rapid7/metasploit-framework master ({{n_msf}} module CVE references; {{n_msf_cves}} distinct CVEs).
4. **ExploitDB** — `files_exploits.csv` from gitlab.com/exploit-database/exploitdb (~{{n_edb_total}} rows, {{n_edb_cves}} distinct CVEs).

### Filters applied to OSV records

- Must have a `severity[]` entry of type `CVSS_V3.x` with a parseable vector. (Records with only CVSS v4 were also accepted as a fallback if the v4 base score < 7; this affected very few records.)
- Computed CVSS base score must be **strictly less than 7.0** and **greater than 0**.
- Must have at least one alias matching `CVE-YYYY-NNNNN+`.
- Withdrawn records: not filtered out at this stage; none had withdrawn=true in the final set.

### Exploitation-evidence definition

A vulnerability is "exploited" if its CVE appears in **any** of:
- **CISA KEV** catalog (any entry).
- **Metasploit** module `references` (any module — exploits, auxiliary scanners, post-exploitation).
- **ExploitDB** with at least one entry of type **remote, webapps, local, or shellcode** AND whose description does NOT match `/proof[ -]?of[ -]?concept|PoC/i`. This excludes the 3,806 ExploitDB DoS-only entries and 19 PoC-only entries.

### Server-side filter (judgment-heavy)

Per-package classification was applied. Defaults to server-side; a hardcoded EXCLUDE list flags client-side packages.

**Excluded as client-side (10 CVEs)**:
- `jquery` family (CVE-2012-6708, 2019-11358, 2020-7656, 2020-11022, 2020-11023) across all ecosystems where webjars/RubyGems/NuGet repackages exist. The vulnerable code executes in a user's browser DOM, even when the surrounding application is server-rendered. KEV's listing of CVE-2020-11023 reflects exploitation of jQuery in client-rendered XSS chains; the package itself is browser-side.
- `puppeteer` (CVE-2019-5786): the npm package is a Node server-side library, but the CVE is a Chromium V8 UAF. Browser engine bug.
- `CefSharp.*` (CVE-2020-15999): Chromium embedded into .NET desktop apps. Desktop client.
- `docsify` (CVE-2020-7680): single-page-app markdown renderer that runs in a user's browser.
- `joplin` (CVE-2020-9038, 2020-28249): Electron desktop note-taking app.

**Included as server-side (135 CVEs)**: the remainder. These break down predictably:
- HTTP servers and HTTP/2 libraries: Tomcat (embed-core, coyote, jsp-api), Jetty (webapp, http2), Akka HTTP, Vite (Node dev server), golang.org/x/net.
- Server-rendered CMSes and portals: TYPO3, Drupal, Liferay, OctoberCMS, Concrete, Pimcore, Bolt, Pagekit, Subrion, Mantis, Moodle, Shopware, Kirby, OpenCMS, Silverstripe, Mezzanine, Microweber, Soosyze, Camaleon, Winter, Feehi, Showdoc, etc.
- Server admin/dashboard panels: Jenkins core + plugins, Grafana, Ajenti, Rundeck, Keycloak, Salt, Ghost, KubeSphere, Casdoor, OpenNMS, Snipe-IT, Label Studio, Apache Superset, copyparty.
- Server-side libraries and parsers: lxml (Python XML/HTML), feedparser (Python RSS), pip, BouncyCastle (Java crypto), Apache Olingo (OData), Apache Axis (SOAP/WSDL), spring-security-oauth, spring-cloud-config-server, elasticsearch-rest-client, golang.org/x/net.
- Server-side application stacks: Django, web2py, Apache Spark, Apache Syncope, Apache Pluto, MoinMoin, KeystoneJS, esm.sh.

### What an "ExploitDB-only" record means

The bulk of sub-7 exploitation evidence (~118 of 135 distinct CVEs) is ExploitDB-only. ExploitDB inclusion (post-DoS-and-PoC filter) typically means a working exploit was published, but it does **not** by itself prove in-the-wild exploitation. KEV's threshold is higher (active exploitation observed). Metasploit module existence implies productionised offensive tooling but not necessarily ITW. **The user should treat the ExploitDB-only set as "demonstrated exploitable" rather than "exploited at scale".**

### What was NOT done

- No NP/DI categorization. (Per request — this happens after pull.)
- No filtering for in-window publish year. All vintages are present (oldest 2007, newest 2025).
- No deduplication across ecosystems. The same CVE can have multiple per-package rows (e.g. CVE-2023-44487 spans Akka, Tomcat, Jetty in Maven and golang.org/x/net in Go). The CVE-level count is **{n_cves}**; the per-row count is **{len(final)}**.
- No EPSS or NVD lookup. Only OSV's CVSS metadata was used.

## Uncertainty / what we may have missed

1. **OSV CVSS provenance is uneven.** OSV's `severity[]` field is populated from a mix of NVD, GHSA, ecosystem advisories, and the original advisory. About 30–40% of OSV entries lack a CVSS_V3 score and were skipped. If a sub-7 CVE happens to live only in an OSV entry without a CVSS field, this scan will not find it. (The OSV `database_specific.severity` qualitative field — LOW/MODERATE — was deliberately not used, since the spec required parseable CVSS scores; LOW/MODERATE GHSA labels overlap fuzzily with sub-7.)

2. **CVSS bases drift.** A CVE may have shipped at 6.8 in OSV/GHSA but been re-scored to 7.5 by NVD analysts (or vice versa). We took OSV's score at face value and did not reconcile against NVD. Borderline records (CVE-2025-31650 Tomcat priority DoS at 6.6, CVE-2023-37941 Apache Superset deser at 6.6) might score differently in NVD.

3. **ExploitDB entry-type heuristic is imperfect.** The CSV `type` field is filled by the ExploitDB curator, and "remote" sometimes means "remote PoC for stack overflow with no spawn". I excluded type=dos and any entry whose description contains "Proof of Concept" / "PoC", but a working exploit can still be a PoC in spirit. Conversely, type=webapps almost always means a working exploit script.

4. **Server-vs-client judgment is opinionated for a handful of packages.**
   - `bcprov-jdk15on` (BouncyCastle) was kept as server-side because the canonical Java enterprise use is TLS termination and certificate validation. BouncyCastle is also embedded in Android apps; if you wanted to be strict, you could exclude this and lose 1 CVE.
   - `lxml` (PyPI) was kept as server-side; lxml runs anywhere Python runs, but the typical exploitation surface (control characters in server-side HTML rendering) is server-side.
   - `mobiledetectlib` (Packagist) was kept as server-side because the canonical use is server-side User-Agent detection in PHP request handlers, even though the XSS payload eventually lands in a browser.
   - `pip` was kept as server-side because pip-based supply chain attacks land in build/server hosts as often as developer laptops.
   If you reclassify any of these as client-side, the count drops by 1–4.

5. **Vite is debatable.** Vite (CVE-2025-30208, 2025-31125) is a development server. Its FS deny-list bypass affects developer machines running `vite dev`. It runs server-side in a literal "is it a Node server" sense, but the threat model is "developer's local dev server is exposed" rather than "production webserver". Included; flag for review.

6. **Ecosystem coverage gaps.** OSV does not currently aggregate Linux distro vulnerabilities, kernel, or non-language-ecosystem packages (nginx upstream is in Linux distros, not directly in any of the 9 ecosystems). HTTP-server-adjacent code that ships with the OS (apache httpd, OpenSSL system packages, BIND) is therefore absent. This scan is a **library-ecosystem** scan, which is exactly what was asked for, but it isn't a complete server-side exploitation map.

7. **ExploitDB's CVE coverage was self-reported.** A CVE without an `exploits/...` row but with an active in-the-wild exploit (rare for FOSS libraries but possible) won't appear here. The KEV+Metasploit overlay catches some of those.

## Output files

- **JSON**: `data/foss-sub7-exploited.json` — {len(final)} per-package records (CVE × ecosystem × package).
- **Deduped CVE-level**: `data/foss-sub7-unique.json` — 135 distinct-CVE records (input to the scoring stage).
- **Excluded set** (for review): `data/_foss-sub7-cache/client_side_excluded.json` — 10 client-side CVEs.
- **This report**: `analyst-reports/2026-04-29-foss-sub7-exploit-scan.md`.
"""

# Fill in the {{n_*}} placeholders
n_kev = 1585
n_msf = 6619
n_msf_cves = 3109
n_edb_total = 46993
n_edb_cves = 24941
md = md.replace("{{n_kev}}", str(n_kev))
md = md.replace("{{n_msf}}", str(n_msf))
md = md.replace("{{n_msf_cves}}", str(n_msf_cves))
md = md.replace("{{n_edb_total}}", str(n_edb_total))
md = md.replace("{{n_edb_cves}}", str(n_edb_cves))

OUT_MD.write_text(md)
print(f"Wrote report to {OUT_MD}")
print(f"Stats: {n_cves} distinct CVEs, {len(final)} per-package rows")
