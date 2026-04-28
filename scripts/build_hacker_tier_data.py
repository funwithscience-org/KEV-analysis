#!/usr/bin/env python3
"""
Build structured hacker-tier and WAF-defensibility JSON files from the
analyst-report markdown + base manifests. These feed the integrated
periodicity page (chart data, per-event tables) and replace the previously
in-HTML-hardcoded numbers.

Outputs:
  - data/hacker-tiers.json — per-CVE tier judgments (S/A/B/C/D) across
    all hacker rounds (R3 Java/Spring, R4 Django, R6 Node+Netty 12mo,
    R7 pre-2018 backfill, R8 OS container).
  - data/waf-defensibility.json — FRIENDLY/MEDIUM/HOSTILE tag for each
    of the actually-exploited events on the 7-year production
    manifest, sourced from R5 (WAF-aware Java run).
  - data/integrated-page-aggregates.json — derived per-month and
    per-year strategy counts that the integrated page renders. The 7-year
    aggregates (per-quarter, per-year, strategy-efficiency) are
    re-derived on every run from data/seven-year-manifest-events.json
    plus the HACKER_TIERS dict below; no longer hardcoded as Python
    literals.
"""
from __future__ import annotations
import datetime as dt
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# ── 7-year manifest derivation constants ──────────────────────────
# DQ rescue CVEs: events that are NP-positive but DI-negative under
# the strict CWE rule, rescued by AI-assisted CWE re-validation. Documented
# in analyst-reports/2026-04-{25,26}-hacker-ranking-v*.md and the
# periodicity §7 prose.
DQ_RESCUE_CVES = {"CVE-2020-1938", "CVE-2025-24813", "CVE-2026-34197"}

# Quarter labels for the 18Q4 → 26Q2 chart window (31 buckets).
SEVEN_YEAR_QUARTER_LABELS = []
for _y in range(2018, 2027):
    for _q in range(1, 5):
        if _y == 2018 and _q < 4:
            continue
        if _y == 2026 and _q > 2:
            continue
        SEVEN_YEAR_QUARTER_LABELS.append(f"{_y}-Q{_q}")
assert len(SEVEN_YEAR_QUARTER_LABELS) == 31

# Year-row labels matching the existing periodicity §7 table.
SEVEN_YEAR_ROW_LABELS = ["2018", "2019", "2020", "2021", "2022", "2023", "2024", "2025", "2026 (Q1+Q2)"]


def _quarter_of(iso_date: str) -> str:
    y, m = int(iso_date[:4]), int(iso_date[5:7])
    return f"{y}-Q{(m - 1) // 3 + 1}"


def _cluster_count(dates: list[str], window_days: int = 7) -> int:
    """Number of 7-day-clustered patch events for a list of disclosure dates.

    A cluster is a maximal run of consecutive sorted dates where each
    adjacent pair sits within `window_days`. Matches the periodicity
    §7 framing: 'if you're already rebuilding when the next CVE drops,
    that's one cycle, not two.'
    """
    if not dates:
        return 0
    parsed = sorted(datetime.strptime(d, "%Y-%m-%d") for d in dates)
    clusters = 1
    for prev, cur in zip(parsed, parsed[1:]):
        if (cur - prev).days > window_days:
            clusters += 1
    return clusters

# ── Hacker tier judgments per CVE ─────────────────────────────────
# Sourced from analyst reports R3-R8. Tier values: S, A, B, C, D, "n/a"
HACKER_TIERS = {
    # === R3 Java/Spring 175-event ranking (subset shown for the 22 events
    # in the Spring 12-month window; full R3 covers 175 events) ===
    # Spring 12-month (Apr 2025 – Apr 2026)
    "CVE-2025-22235": {"tier": "A", "round": "R3", "package": "spring-boot",
                        "rationale": "Actuator exposure → RCE via Jolokia/loggers/env"},
    "CVE-2025-27820": {"tier": "C", "round": "R3", "package": "httpclient5",
                        "rationale": "TLS hostname check disabled — needs MITM"},
    "CVE-2025-41232": {"tier": "A", "round": "R3", "package": "spring-security",
                        "rationale": "Auth bypass for method security on private methods"},
    "CVE-2025-41248": {"tier": "A", "round": "R3", "package": "spring-security",
                        "rationale": "Annotation auth bypass; broad reach, direct primitive"},
    "CVE-2025-41249": {"tier": "A", "round": "R3", "package": "spring-core",
                        "rationale": "Annotation detection auth bypass — broad reach"},
    "CVE-2025-48988": {"tier": "D", "round": "R3", "package": "tomcat", "rationale": "DoS"},
    "CVE-2025-48989": {"tier": "D", "round": "R3", "package": "tomcat", "rationale": "DoS"},
    "CVE-2025-49146": {"tier": "B", "round": "R3", "package": "pgjdbc",
                        "rationale": "Auth-step bypass requires malicious PG server"},
    "CVE-2025-52520": {"tier": "D", "round": "R3", "package": "tomcat", "rationale": "DoS"},
    "CVE-2025-52999": {"tier": "D", "round": "R3", "package": "jackson-core",
                        "rationale": "Stack overflow DoS"},
    "CVE-2025-53506": {"tier": "D", "round": "R3", "package": "tomcat", "rationale": "DoS"},
    "CVE-2025-55752": {"tier": "B", "round": "R3", "package": "tomcat",
                        "rationale": "Path traversal — encoding bypass; non-default reach"},
    "CVE-2026-22732": {"tier": "C", "round": "R3", "package": "spring-security",
                        "rationale": "Defense-in-depth header weakening"},
    "CVE-2026-24734": {"tier": "D", "round": "R3", "package": "tomcat",
                        "rationale": "Generic input validation; DoS-ish"},
    "CVE-2026-29129": {"tier": "D", "round": "R3", "package": "tomcat",
                        "rationale": "Cipher preference order — config bug only"},
    "CVE-2026-29145": {"tier": "A", "round": "R3", "package": "tomcat",
                        "rationale": "CLIENT_CERT auth bypass (mTLS minority surface)"},
    "CVE-2026-34483": {"tier": "D", "round": "R3", "package": "tomcat",
                        "rationale": "JSON-error / log injection"},
    "CVE-2026-34487": {"tier": "D", "round": "R3", "package": "tomcat",
                        "rationale": "Sensitive info into log file"},
    "CVE-2026-40477": {"tier": "A", "round": "R3", "package": "thymeleaf",
                        "rationale": "SSTI primitive when attacker influences template"},
    "CVE-2026-40478": {"tier": "A", "round": "R3", "package": "thymeleaf",
                        "rationale": "SSTI primitive — same class as -40477"},
    "CVE-2026-34197": {"tier": "A", "round": "R3", "package": "activemq-broker",
                        "rationale": "Authenticated Jolokia MBean RCE"},
    # 7-year exploited events (NP+DI catches only — full R3 catches more in S+A)
    "CVE-2021-39144": {"tier": "S", "round": "R3", "package": "xstream",
                        "rationale": "Unauth deser RCE — CWE-306 missing-auth co-tag"},
    "CVE-2021-44228": {"tier": "S", "round": "R3", "package": "log4j-core",
                        "rationale": "JNDI in any logged string — Log4Shell"},
    "CVE-2021-45046": {"tier": "S", "round": "R3", "package": "log4j-core",
                        "rationale": "JNDI patch-bypass"},
    "CVE-2022-22965": {"tier": "A", "round": "R3", "package": "spring-framework",
                        "rationale": "Spring4Shell ClassLoader RCE"},
    "CVE-2022-42889": {"tier": "A", "round": "R3", "package": "commons-text",
                        "rationale": "${url:} interpolation"},
    "CVE-2022-1471":  {"tier": "S", "round": "R3", "package": "snakeyaml",
                        "rationale": "Constructor deser RCE on default config"},
    "CVE-2025-24813": {"tier": "A", "round": "R3", "package": "tomcat",
                        "rationale": "Partial-PUT chained deser"},
    "CVE-2020-1938":  {"tier": "A", "round": "R3", "package": "tomcat",
                        "rationale": "AJP file read (Ghostcat) — WAF-hostile"},
    "CVE-2019-0232":  {"tier": "B", "round": "R3", "package": "tomcat",
                        "rationale": "CGI cmd inj — narrow precondition (Win + CGI on)"},

    # === R4 Django 181-event ranking (subset shown for 18 events in Django 12-month) ===
    "CVE-2025-48379": {"tier": "B", "round": "R4", "package": "pillow",
                        "rationale": "BCn encoding write buffer overflow — narrow"},
    "CVE-2025-57833": {"tier": "A", "round": "R4", "package": "django",
                        "rationale": "Column aliases SQLi via annotate()/values()"},
    "CVE-2025-59681": {"tier": "A", "round": "R4", "package": "django",
                        "rationale": "Column aliases SQLi — same shape"},
    "CVE-2025-64459": {"tier": "A", "round": "R4", "package": "django",
                        "rationale": "_connector kwarg SQLi — direct injection"},
    "CVE-2025-64458": {"tier": "D", "round": "R4", "package": "django", "rationale": "DoS"},
    "CVE-2025-66471": {"tier": "C", "round": "R4", "package": "urllib3",
                        "rationale": "Decompression bomb — partial defense bypass"},
    "CVE-2025-66418": {"tier": "C", "round": "R4", "package": "urllib3",
                        "rationale": "Decompression chain"},
    "CVE-2026-21441": {"tier": "B", "round": "R4", "package": "urllib3",
                        "rationale": "Redirect bypass of decompression safeguard"},
    "CVE-2026-1287":  {"tier": "B", "round": "R4", "package": "django",
                        "rationale": "SQLi cluster — cluster mean default"},
    "CVE-2026-1207":  {"tier": "B", "round": "R4", "package": "django",
                        "rationale": "SQLi cluster"},
    "CVE-2026-26007": {"tier": "B", "round": "R4", "package": "cryptography",
                        "rationale": "SECT curves invalid-curve attack — gated on usage"},
    "CVE-2026-25990": {"tier": "B", "round": "R4", "package": "pillow",
                        "rationale": "PSD OOB write — narrow reach"},
    "CVE-2026-25673": {"tier": "D", "round": "R4", "package": "django", "rationale": "DoS"},
    "CVE-2026-32274": {"tier": "D", "round": "R4", "package": "black",
                        "rationale": "Dev-tool — not production attack surface"},
    "CVE-2026-32597": {"tier": "B", "round": "R4", "package": "pyjwt",
                        "rationale": "Unknown crit header bypass — gated on app use"},
    "CVE-2026-33034": {"tier": "B", "round": "R4", "package": "django",
                        "rationale": "Content-Length DoS / stacking precondition"},
    "CVE-2026-3902":  {"tier": "A", "round": "R4", "package": "django",
                        "rationale": "ASGI header spoof — direct auth bypass when proxy-trust pattern present"},
    "CVE-2026-40192": {"tier": "D", "round": "R4", "package": "pillow",
                        "rationale": "DoS / resource exhaustion"},

    # === R6 Node + Netty 12-month ranking (23 events) ===
    "CVE-2025-47935": {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS via memory leak"},
    "CVE-2025-47944": {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2025-48997": {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2025-7338":  {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2025-58754": {"tier": "D", "round": "R6", "package": "axios", "rationale": "DoS"},
    "CVE-2025-14874": {"tier": "D", "round": "R6", "package": "nodemailer", "rationale": "Address parser regex DoS"},
    "CVE-2026-25223": {"tier": "C", "round": "R6", "package": "fastify", "rationale": "Validation bypass"},
    "CVE-2026-25639": {"tier": "C", "round": "R6", "package": "axios", "rationale": "Prototype pollution — server reach limited"},
    "CVE-2026-27959": {"tier": "B", "round": "R6", "package": "koa", "rationale": "Host header injection"},
    "CVE-2026-2359":  {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2026-3304":  {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2026-3520":  {"tier": "D", "round": "R6", "package": "multer", "rationale": "DoS"},
    "CVE-2026-30951": {"tier": "A", "round": "R6", "package": "sequelize", "rationale": "ORM-layer SQLi via JSON column casting"},
    "CVE-2026-33937": {"tier": "A", "round": "R6", "package": "handlebars", "rationale": "SSTI via AST type confusion"},
    "CVE-2026-33938": {"tier": "A", "round": "R6", "package": "handlebars", "rationale": "SSTI — same class"},
    "CVE-2026-33939": {"tier": "D", "round": "R6", "package": "handlebars", "rationale": "DoS"},
    "CVE-2026-33940": {"tier": "A", "round": "R6", "package": "handlebars", "rationale": "SSTI — same class"},
    "CVE-2026-33941": {"tier": "C", "round": "R6", "package": "handlebars", "rationale": "CLI Precompiler — build-time only"},
    "CVE-2026-4800":  {"tier": "A", "round": "R6", "package": "lodash", "rationale": "_.template code injection"},
    "CVE-2026-33806": {"tier": "C", "round": "R6", "package": "fastify", "rationale": "Body schema validation bypass"},
    "CVE-2026-33870": {"tier": "A", "round": "R6", "package": "netty-codec-http", "rationale": "HTTP request smuggling via chunked extension"},
    "CVE-2025-55163": {"tier": "D", "round": "R6", "package": "netty-codec-http2", "rationale": "MadeYouReset HTTP/2 DDoS"},
    "CVE-2026-33871": {"tier": "D", "round": "R6", "package": "netty-codec-http2", "rationale": "HTTP/2 CONTINUATION DoS"},

    # === R7 pre-2018 backfill on production manifest exploited events ===
    "CVE-2013-7285":  {"tier": "A", "round": "R7", "package": "xstream",
                        "rationale": "OS command via XML — pre-1.4.18 unsafe-default era"},
    "CVE-2017-12615": {"tier": "B", "round": "R7", "package": "tomcat",
                        "rationale": "HTTP PUT JSP upload — narrow precondition (readonly=false)"},
    "CVE-2017-12617": {"tier": "B", "round": "R7", "package": "tomcat",
                        "rationale": "HTTP PUT (Win variant) — same precondition"},

    # === R9-retro canonical anchor — added 2026-04-27 from
    # analyst-reports/2026-04-27-retrospective-30day-sweep.md
    # Closes the "edge-appliance auth-bypass + RCE" anchor gap. The April-2026 KEV
    # inbound included ~10-15 events in this class (Cisco SD-WAN, Fortinet
    # FortiClient EMS, F5 BIG-IP, JetBrains TeamCity, Quest KACE, PaperCut,
    # Synacor Zimbra, Citrix NetScaler, Kentico) that were all landing as
    # tier_anchor: "novel" in the retro run because no canonical existed.
    # Pattern signature: vendor appliance / management plane, unauthenticated
    # or near-default-auth, network-edge HTTP/HTTPS surface, primitive-direct
    # RCE via input handling. Future analyst runs encountering this shape
    # should cite this anchor instead of stamping novel.
    "CVE-2026-1340":  {"tier": "A", "round": "R9-retro", "package": "Ivanti EPMM",
                        "rationale": "Edge-appliance auth-bypass + unauth RCE via code injection — canonical for vendor-appliance management-plane exploitation pattern",
                        "canonical_for": "edge-appliance-auth-bypass-rce"},
}

# ── R8 OS-container hacker pass — summary only (most events are NVD noise) ──
OS_HACKER_R8 = {
    "summary": {
        "total_events": 69,
        "after_nvd_noise_clean": 18,
        "tier_S": 0,
        "tier_A_unconditional": 0,
        "tier_A_conditional_post_compromise_kernel": "2-3",
        "tier_B_conditional": "2-6",
        "tier_C": "6-8",
        "tier_D_including_noise": "50+",
    },
    "noise_breakdown": {
        "sqlite_27_events": "~24 are downstream apps (FUXA, METIS, n8n, langchain, etc.); ~3 actual SQLite lib bugs",
        "systemd_15_events": "~7 are kernel CVEs keyword-matched via systemd; rest are unrelated apps (BlueChi, snapd, Incus, Himmelblau, OpenClaw); 0 actual systemd bugs",
        "zlib_8_events": "~3 actual zlib lib bugs; rest are downstream consumers (Compress::Raw::Zlib, undici, Open Babel, Unfurl)",
    },
    "structural_finding": "Reproduces NP+DI = 0 from the published periodicity. The OS layer doesn't drive emergency rebuild cadence under either filter. Real LPE-relevant surface is ~5-10 bugs/year, not the published 21.",
}

# ── WAF defensibility for the 13 actually-exploited 7-year events ──
WAF_DEFENSIBILITY = {
    "CVE-2017-12615": {"waf": "FRIENDLY", "rationale": "PUT method + .jsp upload signature-able same-day"},
    "CVE-2017-12617": {"waf": "FRIENDLY", "rationale": "Same as above"},
    "CVE-2013-7285":  {"waf": "MEDIUM",   "rationale": "Class-name signature evadable, gadget zoo wide"},
    "CVE-2019-0232":  {"waf": "FRIENDLY", "rationale": "CGI command-injection patterns are CRS-1"},
    "CVE-2020-1938":  {"waf": "HOSTILE",  "rationale": "AJP is binary on port 8009 — WAF doesn't see it"},
    "CVE-2021-39144": {"waf": "MEDIUM",   "rationale": "Class-name signature evadable"},
    "CVE-2021-44228": {"waf": "MEDIUM",   "rationale": "${jndi:} patterns shipped same-day; Unicode obfuscation extended window"},
    "CVE-2021-45046": {"waf": "MEDIUM",   "rationale": "Even more obfuscation room than -44228"},
    "CVE-2022-22965": {"waf": "FRIENDLY", "rationale": "class.module.classLoader rule shipped within hours"},
    "CVE-2022-42889": {"waf": "FRIENDLY", "rationale": "${url:}/${script:} patterns signature-able same-day"},
    "CVE-2022-1471":  {"waf": "MEDIUM",   "rationale": "YAML body parsing varies by WAF; !!javax.script tag detectable"},
    "CVE-2025-24813": {"waf": "MEDIUM",   "rationale": "Two-step PUT-then-GET chain distributed across requests"},
    "CVE-2026-34197": {"waf": "MEDIUM",   "rationale": "JSON-to-MBean patterns visible; Jolokia often deployment-internal"},
}

# ── Per-month per-strategy framework data (12-month window, Apr 2025 – Apr 2026) ──
# Each list is 13 months: Apr 25, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec, Jan 26, Feb, Mar, Apr 26
PER_MONTH_FRAMEWORK = {
    "months": ["2025-04","2025-05","2025-06","2025-07","2025-08","2025-09","2025-10","2025-11","2025-12","2026-01","2026-02","2026-03","2026-04"],
    "spring": {"other": [2,0,3,2,1,1,0,0,0,0,1,1,2], "npdi_raw": [0,1,0,0,0,1,1,0,0,0,0,0,6], "ai_rescue_added": [0,0,0,0,0,0,0,0,0,0,0,0,0], "hacker_sa": [1,1,0,0,0,2,0,0,0,0,0,0,5]},
    "nodejs": {"other": [0,2,1,1,0,1,0,0,1,0,2,4,1], "npdi_raw": [0,0,0,0,0,0,0,0,0,0,1,4,0], "ai_rescue_added": [0,0,0,0,0,0,0,0,0,0,0,1,1], "hacker_sa": [0,0,0,0,0,0,0,0,0,0,0,4,1]},
    "django": {"other": [0,0,0,1,0,0,0,1,2,1,1,2,2], "npdi_raw": [0,0,0,0,0,1,1,1,0,0,3,1,0], "ai_rescue_added": [0,0,0,0,0,0,0,0,0,0,0,0,1], "hacker_sa": [0,0,0,0,0,1,1,1,0,0,0,0,1]},
    "netty":  {"other": [0,0,1,0,1,0,0,0,0,0,0,1,0], "npdi_raw": [0,0,0,0,0,0,0,0,0,0,0,1,0], "ai_rescue_added": [0,0,0,0,0,0,0,0,0,0,0,0,0], "hacker_sa": [0,0,0,0,0,0,0,0,0,0,0,1,0]},
}

# ── 7-year aggregates (production manifest) — DERIVED FROM EVENTS FILE ──
#
# As of 2026-04-28 these are no longer hardcoded. They are derived from
# data/seven-year-manifest-events.json (which itself derives from
# data/_manifest-osv-cache.json) plus the HACKER_TIERS dict above. The
# user-decided canonical scope is "runtime-only" — pure build tooling
# (Maven core, plexus, surefire) and dual-use scripting runtimes (Groovy,
# JRuby, Jython) are excluded; the 4 runtime additions (Apache CXF, MINA,
# SSHD, Hazelcast) are included via the same OSV-backed pipeline as the
# existing 54 packages. See analyst-reports/2026-04-28-seven-year-data-
# reconciliation.md for the audit trail.

def _build_seven_year_aggregates() -> tuple[dict, dict, dict]:
    """Derive the per-quarter, per-year, and strategy-efficiency dicts
    from data/seven-year-manifest-events.json plus HACKER_TIERS."""
    events_path = REPO / "data" / "seven-year-manifest-events.json"
    if not events_path.exists():
        raise FileNotFoundError(
            f"{events_path.relative_to(REPO)} missing. Run "
            f"scripts/build_seven_year_manifest_events.py first."
        )
    events = json.load(open(events_path))["events"]

    sa_set = {cve for cve, t in HACKER_TIERS.items() if t.get("tier") in ("S", "A")}

    def _is_npdi_raw(e):
        return e["is_np"] and e["is_di"]

    def _is_npdi_dq(e):
        return _is_npdi_raw(e) or e["cve"] in DQ_RESCUE_CVES

    def _is_sa(e):
        return e["cve"] in sa_set

    def _is_critical(e):
        return e.get("severity") == "CRITICAL"

    # ── Per-quarter ──
    q_total = defaultdict(int)
    q_npdi_dq = defaultdict(int)
    q_hacker_sa = defaultdict(int)
    for e in events:
        q = _quarter_of(e["published"])
        q_total[q] += 1
        if _is_npdi_dq(e):
            q_npdi_dq[q] += 1
        if _is_sa(e):
            q_hacker_sa[q] += 1
    per_quarter = {
        "quarters": list(SEVEN_YEAR_QUARTER_LABELS),
        # rmOther = all - NP+DI+DQ; rmNPDI = NP+DI+DQ
        "all_ch":     [q_total[q] for q in SEVEN_YEAR_QUARTER_LABELS],
        "npdi_ai":    [q_npdi_dq[q] for q in SEVEN_YEAR_QUARTER_LABELS],
        "hacker_sa":  [q_hacker_sa[q] for q in SEVEN_YEAR_QUARTER_LABELS],
        # convenience: rmOther derived for the chart
        "other":      [q_total[q] - q_npdi_dq[q] for q in SEVEN_YEAR_QUARTER_LABELS],
    }

    # ── Per-year (last row is "2026 (Q1+Q2)") ──
    y_buckets = {label: defaultdict(int) for label in SEVEN_YEAR_ROW_LABELS}

    def _year_label(iso_date: str) -> str:
        return "2026 (Q1+Q2)" if iso_date.startswith("2026") else iso_date[:4]

    for e in events:
        yl = _year_label(e["published"])
        b = y_buckets[yl]
        b["all_ch"] += 1
        if _is_npdi_raw(e):
            b["npdi_raw"] += 1
        if _is_npdi_dq(e):
            b["npdi_ai"] += 1
        if _is_sa(e):
            b["hacker_sa"] += 1
        if e["exploited"]:
            b["exploited"] += 1
        if e["exploited"] and _is_sa(e):
            b["hacker_caught"] += 1

    per_year = {}
    totals = defaultdict(int)
    for label in SEVEN_YEAR_ROW_LABELS:
        b = y_buckets[label]
        row = {
            "all_ch":     b["all_ch"],
            "npdi_raw":   b["npdi_raw"],
            "npdi_ai":    b["npdi_ai"],
            "hacker_sa":  b["hacker_sa"],
            "exploited":  b["exploited"],
            "hacker_catches": (
                f"{b['hacker_caught']}/{b['exploited']}"
                if b["exploited"] else None
            ),
        }
        per_year[label] = row
        for k in ("all_ch", "npdi_raw", "npdi_ai", "hacker_sa", "exploited"):
            totals[k] += row[k]
        totals["hacker_caught"] += b["hacker_caught"]
    per_year["Total"] = {
        "all_ch":     totals["all_ch"],
        "npdi_raw":   totals["npdi_raw"],
        "npdi_ai":    totals["npdi_ai"],
        "hacker_sa":  totals["hacker_sa"],
        "exploited":  totals["exploited"],
        "hacker_catches": f"{totals['hacker_caught']}/{totals['exploited']}",
    }

    # ── Strategy efficiency ──
    def _strategy_row(filtered):
        dates = [e["published"] for e in filtered]
        pe = _cluster_count(dates)
        rt = len(filtered)
        ec = sum(1 for e in filtered if e["exploited"])
        total_exp = totals["exploited"]
        eff = ec / total_exp if total_exp else 0.0
        overhead = pe / ec if ec else None
        return {
            "patch_events_clustered": pe,
            "raw_triggers": rt,
            "exploits_caught": ec,
            "effectiveness": round(eff, 3),
            "efficiency_overhead": round(overhead, 2) if overhead is not None else None,
        }

    npdi_raw_set = [e for e in events if _is_npdi_raw(e)]
    npdi_dq_set = [e for e in events if _is_npdi_dq(e)]
    hacker_sa_set = [e for e in events if _is_sa(e)]
    union_set_cves = {e["cve"] for e in npdi_dq_set} | {e["cve"] for e in hacker_sa_set}
    union_set = [e for e in events if e["cve"] in union_set_cves]
    criticals_set = [e for e in events if _is_critical(e)]

    strategy_efficiency = {
        "patch_all_ch":         _strategy_row(events),
        "patch_criticals":      _strategy_row(criticals_set),
        "npdi_raw":             _strategy_row(npdi_raw_set),
        "npdi_ai":              _strategy_row(npdi_dq_set),
        "hacker_sa":            _strategy_row(hacker_sa_set),
        "union_npdi_ai_hacker": _strategy_row(union_set),
    }

    return per_quarter, per_year, strategy_efficiency


SEVEN_YEAR_PER_QUARTER, SEVEN_YEAR_PER_YEAR, STRATEGY_EFFICIENCY_7YR = \
    _build_seven_year_aggregates()


def main() -> int:
    now = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    base_meta = {
        "generated_at": now,
        "generator": "scripts/build_hacker_tier_data.py",
        "source_reports": [
            "analyst-reports/2026-04-25-hacker-ranking-v3.md (R3 Java/Spring 175-event)",
            "analyst-reports/2026-04-25-hacker-ranking-v4-django.md (R4 Django 181-event)",
            "analyst-reports/2026-04-25-hacker-ranking-v5-java-waf-aware.md (R5 WAF axis)",
            "analyst-reports/2026-04-26-hacker-ranking-v6-node-netty-12mo.md (R6 Node+Netty 12mo)",
            "analyst-reports/2026-04-26-hacker-ranking-v7-pre2018-backfill.md (R7 pre-2018 backfill)",
            "analyst-reports/2026-04-26-hacker-ranking-v8-os-container.md (R8 OS container)",
            "analyst-reports/2026-04-27-retrospective-30day-sweep.md (R9-retro canonical anchor add)",
        ],
        "rounds_in_use_for_integrated_page": ["R3", "R4", "R6", "R7", "R8"],
        "canonical_anchors": {
            "edge-appliance-auth-bypass-rce": {
                "anchor_cve": "CVE-2026-1340",
                "added": "2026-04-27",
                "rationale": "Vendor-appliance management plane (MDM, SD-WAN, EMS, BIG-IP, etc.), unauthenticated or near-default auth, network-edge HTTP/HTTPS surface, primitive-direct RCE via input handling. Tier A."
            }
        },
    }

    out_tiers = {**base_meta, "n_cves": len(HACKER_TIERS), "tiers": HACKER_TIERS,
                  "os_round_summary": OS_HACKER_R8}
    (REPO / "data" / "hacker-tiers.json").write_text(json.dumps(out_tiers, indent=2))
    print(f"wrote data/hacker-tiers.json ({len(HACKER_TIERS)} CVEs)")

    out_waf = {**base_meta, "n_cves": len(WAF_DEFENSIBILITY),
                "definitions": {
                    "FRIENDLY": "Signature-able payload, generic OWASP rules cover, emergency rule ships within hours",
                    "MEDIUM":   "Signature exists but evadable (encoding, obfuscation, format gaps)",
                    "HOSTILE":  "Wrong protocol entirely or attack indistinguishable from legitimate traffic",
                },
                "events": WAF_DEFENSIBILITY}
    (REPO / "data" / "waf-defensibility.json").write_text(json.dumps(out_waf, indent=2))
    print(f"wrote data/waf-defensibility.json ({len(WAF_DEFENSIBILITY)} CVEs)")

    out_agg = {**base_meta,
                "per_month_framework": PER_MONTH_FRAMEWORK,
                "seven_year_per_quarter": SEVEN_YEAR_PER_QUARTER,
                "seven_year_per_year": SEVEN_YEAR_PER_YEAR,
                "strategy_efficiency_7yr": STRATEGY_EFFICIENCY_7YR}
    (REPO / "data" / "integrated-page-aggregates.json").write_text(json.dumps(out_agg, indent=2))
    print(f"wrote data/integrated-page-aggregates.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
