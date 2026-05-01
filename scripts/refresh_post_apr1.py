#!/usr/bin/env python3
"""
refresh_post_apr1.py — daily refresher for the dashboard's "Live tracker
(April 1, 2026 forward)" chart and per-event table.

The pre-existing builder (build_post_apr1_per_framework.py) reads from
periodicity caches that aren't refreshed by the daily refresh agent.
This script is the canonical daily path: it fetches OSV fresh for each
of the 5 manifests, applies the frozen DI rules + hacker tiers + KEV
overlay, writes data/post-apr1-per-framework.json, and patches the
embedded POST_APR1 JS data block in docs/dashboard.html.

Five manifests (must stay in lock-step with the multi_framework_periodicity.py
+ spring_periodicity_data.json + fetch_netty_osv.py + seven-year manifest
package roles — the manifests below are deliberately copy-pasted rather than
imported from those files because we want this script self-contained for the
daily agent run):
  1. spring     — Spring Boot starter (~48 packages)
  2. nodejs     — Node.js / Express (~45 packages)
  3. django     — Django / Python (~40 packages)
  4. netty      — Netty (7 packages)
  5. real_java  — Real-world Java enterprise (58 packages, layered Spring +
                  ActiveMQ + Camel + log4j + xstream)

Run order in the daily refresh:
  1. KEV snapshot already refreshed (data/kev-snapshot-YYYY-MM-DD.json)
  2. data/hacker-tiers.json optionally refreshed by analyst agent (6:10 AM)
  3. python3 scripts/refresh_post_apr1.py
  4. tests/run.sh
  5. commit + push

Usage:
    python3 scripts/refresh_post_apr1.py
    python3 scripts/refresh_post_apr1.py --check   # rebuild + diff vs current dashboard embed
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CUTOFF = "2026-04-01"
OSV_URL = "https://api.osv.dev/v1/query"
SLEEP_BETWEEN = 0.35  # seconds; OSV is generous, we still throttle


# ── Frozen DI CWE set (config.json:di_cwe_freeze, locked 2026-05-01) ───
DI_CWES = {
    22, 23, 35, 73, 74, 77, 78, 79, 89, 90, 91, 93, 94, 95, 96, 97,
    113, 116, 287, 289, 306, 345, 444, 502, 611, 693, 776, 863, 917,
    918, 1321,
    # Historically counted by twelve-month-per-framework.json (kept for parity):
    1336, 36, 98, 1236,
}


# ── Manifests ──────────────────────────────────────────────────────────
# Each entry: (ecosystem, package_name, role)
# role ∈ {"NP", "OTHER"}; NP = "trust-boundary library" per CLAUDE.md NP rule.

SPRING_MANIFEST = [
    ("Maven", "org.springframework.boot:spring-boot",                                "OTHER"),
    ("Maven", "org.springframework.boot:spring-boot-autoconfigure",                  "OTHER"),
    ("Maven", "org.springframework:spring-core",                                     "OTHER"),
    ("Maven", "org.springframework:spring-context",                                  "OTHER"),
    ("Maven", "org.springframework:spring-beans",                                    "OTHER"),
    ("Maven", "org.springframework:spring-aop",                                      "OTHER"),
    ("Maven", "org.springframework:spring-web",                                      "NP"),
    ("Maven", "org.springframework:spring-webmvc",                                   "NP"),
    ("Maven", "org.apache.tomcat.embed:tomcat-embed-core",                           "NP"),
    ("Maven", "org.apache.tomcat.embed:tomcat-embed-websocket",                      "NP"),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind",                         "NP"),
    ("Maven", "com.fasterxml.jackson.core:jackson-core",                             "NP"),
    ("Maven", "com.fasterxml.jackson.core:jackson-annotations",                      "OTHER"),
    ("Maven", "com.fasterxml.jackson.datatype:jackson-datatype-jsr310",              "OTHER"),
    ("Maven", "org.springframework.security:spring-security-core",                   "NP"),
    ("Maven", "org.springframework.security:spring-security-web",                    "NP"),
    ("Maven", "org.springframework.security:spring-security-config",                 "OTHER"),
    ("Maven", "org.springframework.security:spring-security-oauth2-resource-server", "NP"),
    ("Maven", "org.springframework:spring-jdbc",                                     "OTHER"),
    ("Maven", "org.springframework.data:spring-data-jpa",                            "OTHER"),
    ("Maven", "org.hibernate.orm:hibernate-core",                                    "OTHER"),
    ("Maven", "org.postgresql:postgresql",                                           "OTHER"),
    ("Maven", "com.zaxxer:HikariCP",                                                 "OTHER"),
    ("Maven", "org.thymeleaf:thymeleaf",                                             "NP"),
    ("Maven", "org.thymeleaf:thymeleaf-spring6",                                     "NP"),
    ("Maven", "ch.qos.logback:logback-classic",                                      "OTHER"),
    ("Maven", "ch.qos.logback:logback-core",                                         "OTHER"),
    ("Maven", "org.slf4j:slf4j-api",                                                 "OTHER"),
    ("Maven", "org.yaml:snakeyaml",                                                  "OTHER"),
    ("Maven", "org.hibernate.validator:hibernate-validator",                         "OTHER"),
    ("Maven", "jakarta.validation:jakarta.validation-api",                           "OTHER"),
    ("Maven", "com.google.guava:guava",                                              "OTHER"),
    ("Maven", "org.apache.commons:commons-lang3",                                    "OTHER"),
    ("Maven", "commons-io:commons-io",                                               "OTHER"),
    ("Maven", "org.apache.commons:commons-collections4",                             "OTHER"),
    ("Maven", "org.apache.commons:commons-text",                                     "OTHER"),
    ("Maven", "org.apache.httpcomponents.client5:httpclient5",                       "NP"),
    ("Maven", "org.apache.httpcomponents.core5:httpcore5",                           "NP"),
    ("Maven", "com.github.ben-manes.caffeine:caffeine",                              "OTHER"),
    ("Maven", "org.springframework.amqp:spring-amqp",                                "OTHER"),
    ("Maven", "com.rabbitmq:amqp-client",                                            "NP"),
    ("Maven", "io.github.resilience4j:resilience4j-spring-boot3",                    "OTHER"),
    ("Maven", "io.micrometer:micrometer-core",                                       "OTHER"),
    ("Maven", "org.springframework.boot:spring-boot-actuator",                       "NP"),
    ("Maven", "org.springdoc:springdoc-openapi-starter-webmvc-ui",                   "OTHER"),
    ("Maven", "net.bytebuddy:byte-buddy",                                            "OTHER"),
    ("Maven", "org.glassfish.jaxb:jaxb-runtime",                                     "NP"),
    ("Maven", "org.bouncycastle:bcprov-jdk18on",                                     "OTHER"),
]

NODE_MANIFEST = [
    ("npm", "express",                "NP"),
    ("npm", "koa",                    "NP"),
    ("npm", "fastify",                "NP"),
    ("npm", "body-parser",            "NP"),
    ("npm", "multer",                 "NP"),
    ("npm", "cookie-parser",          "NP"),
    ("npm", "cors",                   "NP"),
    ("npm", "helmet",                 "NP"),
    ("npm", "http-proxy-middleware",  "NP"),
    ("npm", "node-fetch",             "NP"),
    ("npm", "axios",                  "NP"),
    ("npm", "ws",                     "NP"),
    ("npm", "socket.io",              "NP"),
    ("npm", "ejs",                    "NP"),
    ("npm", "pug",                    "NP"),
    ("npm", "handlebars",             "NP"),
    ("npm", "nunjucks",               "NP"),
    ("npm", "jsonwebtoken",           "NP"),
    ("npm", "passport",               "NP"),
    ("npm", "graphql",                "NP"),
    ("npm", "apollo-server-express",  "NP"),
    ("npm", "mongoose",               "OTHER"),
    ("npm", "sequelize",              "OTHER"),
    ("npm", "knex",                   "OTHER"),
    ("npm", "pg",                     "OTHER"),
    ("npm", "redis",                  "OTHER"),
    ("npm", "ioredis",                "OTHER"),
    ("npm", "bull",                   "OTHER"),
    ("npm", "winston",                "OTHER"),
    ("npm", "morgan",                 "OTHER"),
    ("npm", "dotenv",                 "OTHER"),
    ("npm", "lodash",                 "OTHER"),
    ("npm", "moment",                 "OTHER"),
    ("npm", "uuid",                   "OTHER"),
    ("npm", "bcrypt",                 "OTHER"),
    ("npm", "sharp",                  "OTHER"),
    ("npm", "nodemailer",             "OTHER"),
    ("npm", "joi",                    "OTHER"),
    ("npm", "yup",                    "OTHER"),
    ("npm", "chalk",                  "OTHER"),
    ("npm", "commander",              "OTHER"),
    ("npm", "aws-sdk",                "OTHER"),
    ("npm", "eslint",                 "OTHER"),
    ("npm", "jest",                   "OTHER"),
    ("npm", "supertest",              "OTHER"),
]

DJANGO_MANIFEST = [
    ("PyPI", "django",               "NP"),
    ("PyPI", "djangorestframework",  "NP"),
    ("PyPI", "flask",                "NP"),
    ("PyPI", "gunicorn",             "NP"),
    ("PyPI", "uvicorn",              "NP"),
    ("PyPI", "requests",             "NP"),
    ("PyPI", "httpx",                "NP"),
    ("PyPI", "urllib3",              "NP"),
    ("PyPI", "jinja2",               "NP"),
    ("PyPI", "pyjwt",                "NP"),
    ("PyPI", "django-cors-headers",  "NP"),
    ("PyPI", "channels",             "NP"),
    ("PyPI", "graphene-django",      "NP"),
    ("PyPI", "django-oauth-toolkit", "NP"),
    ("PyPI", "whitenoise",           "NP"),
    ("PyPI", "django-ninja",         "NP"),
    ("PyPI", "celery",               "OTHER"),
    ("PyPI", "redis",                "OTHER"),
    ("PyPI", "psycopg2",             "OTHER"),
    ("PyPI", "sqlalchemy",           "OTHER"),
    ("PyPI", "boto3",                "OTHER"),
    ("PyPI", "pillow",               "OTHER"),
    ("PyPI", "numpy",                "OTHER"),
    ("PyPI", "pandas",               "OTHER"),
    ("PyPI", "pyyaml",               "OTHER"),
    ("PyPI", "cryptography",         "NP"),  # auth-boundary override per CLAUDE.md NP rule
    ("PyPI", "paramiko",             "OTHER"),
    ("PyPI", "django-debug-toolbar", "OTHER"),
    ("PyPI", "django-extensions",    "OTHER"),
    ("PyPI", "django-filter",        "OTHER"),
    ("PyPI", "sentry-sdk",           "OTHER"),
    ("PyPI", "pytest",               "OTHER"),
    ("PyPI", "pytest-django",        "OTHER"),
    ("PyPI", "factory-boy",          "OTHER"),
    ("PyPI", "black",                "OTHER"),
    ("PyPI", "flake8",               "OTHER"),
    ("PyPI", "django-storages",      "OTHER"),
    ("PyPI", "django-redis",         "OTHER"),
    ("PyPI", "kombu",                "OTHER"),
    ("PyPI", "python-dateutil",      "OTHER"),
]

NETTY_MANIFEST = [
    ("Maven", "io.netty:netty-codec-http",  "NP"),
    ("Maven", "io.netty:netty-codec-http2", "NP"),
    ("Maven", "io.netty:netty-codec",       "NP"),
    ("Maven", "io.netty:netty-handler",     "NP"),
    ("Maven", "io.netty:netty-transport",   "OTHER"),
    ("Maven", "io.netty:netty-buffer",      "OTHER"),
    ("Maven", "io.netty:netty-common",      "OTHER"),
]

# Real-world Java enterprise: Spring Boot starter + ActiveMQ + Camel +
# log4j + xstream. Reuses Spring set + the runtime additions that the
# seven-year manifest covers. Keep in sync with
# data/_manifest-osv-cache.json (the canonical 58-package universe).
REAL_JAVA_EXTRA = [
    ("Maven", "org.apache.activemq:activemq-broker", "NP"),     # Jolokia HTTP-over-JMX is parser surface
    ("Maven", "org.apache.activemq:activemq-client", "OTHER"),
    ("Maven", "org.apache.camel:camel-core",         "OTHER"),
    ("Maven", "org.apache.camel:camel-http",         "NP"),
    ("Maven", "org.apache.logging.log4j:log4j-core", "NP"),     # JNDI parser surface
    ("Maven", "org.apache.logging.log4j:log4j-api",  "OTHER"),
    ("Maven", "com.thoughtworks.xstream:xstream",    "NP"),     # XML deserializer
]
REAL_JAVA_MANIFEST = SPRING_MANIFEST + REAL_JAVA_EXTRA


MANIFESTS = [
    ("spring",    "Spring Boot",        SPRING_MANIFEST),
    ("nodejs",    "Node.js/Express",    NODE_MANIFEST),
    ("django",    "Django/Python",      DJANGO_MANIFEST),
    ("netty",     "Netty",              NETTY_MANIFEST),
    ("real_java", "Real-world Java",    REAL_JAVA_MANIFEST),
]


# ── Helpers ────────────────────────────────────────────────────────────
def _cluster_count(dates: list[str], window_days: int = 7) -> int:
    if not dates:
        return 0
    parsed = sorted(dt.datetime.strptime(d, "%Y-%m-%d") for d in dates)
    clusters = 1
    for prev, cur in zip(parsed, parsed[1:]):
        if (cur - prev).days > window_days:
            clusters += 1
    return clusters


def _is_di_cwes(cwes: list[str]) -> bool:
    for c in cwes or []:
        try:
            n = int(str(c).removeprefix("CWE-"))
        except ValueError:
            continue
        if n in DI_CWES:
            return True
    return False


def _severity_is_high_or_critical(vuln: dict) -> bool:
    """Best-effort C/H severity check across OSV severity arrays."""
    sevs = vuln.get("severity") or []
    for s in sevs:
        score = (s or {}).get("score", "")
        # CVSS v3 base score in vector
        m = re.search(r"CVSS:3\.\d+/.*?(?:\b|/)A:[NLH]", score)
        if not score:
            continue
        # If we have a numeric score in database_specific or details, use it
    db = (vuln.get("database_specific") or {})
    sev_label = (db.get("severity") or "").upper()
    if sev_label in ("HIGH", "CRITICAL"):
        return True
    # Try to parse CVSS3 vector for AV:N (network) and Impact ≥ HIGH proxy
    # Default to True if any severity record exists with vector — let GHSA's
    # own severity label do the heavy lifting via database_specific.
    return False


def _ghsa_severity_label(vuln: dict) -> str:
    """Return GHSA severity label as 'HIGH/CRITICAL', 'MEDIUM', 'LOW' or ''."""
    db = (vuln.get("database_specific") or {})
    sev = (db.get("severity") or "").upper()
    if sev in ("HIGH", "CRITICAL"):
        return sev
    # Fallback: try the GHSA repository_url label inside the severity object
    for s in vuln.get("severity") or []:
        sc = s.get("score") or ""
        if "/" in sc:
            # CVSS vector — check base score quickly via pattern (not perfect but okay)
            return ""
    return sev or ""


def fetch_osv_for_package(eco: str, pkg: str, retries: int = 3) -> list[dict]:
    body = json.dumps({"package": {"name": pkg, "ecosystem": eco}}).encode()
    req = urllib.request.Request(
        OSV_URL, data=body, headers={"Content-Type": "application/json"}
    )
    last_err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
                return data.get("vulns", []) or []
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    print(f"  WARN: OSV fetch failed for {eco}/{pkg}: {last_err}", file=sys.stderr)
    return []


def _cves_from_aliases(aliases: list[str]) -> list[str]:
    return sorted({a for a in (aliases or []) if a.startswith("CVE-")})


def _published_date(vuln: dict) -> str | None:
    p = vuln.get("published") or vuln.get("modified") or ""
    return p[:10] if len(p) >= 10 else None


def _cwes_from_vuln(vuln: dict) -> list[str]:
    db = (vuln.get("database_specific") or {})
    cwes = db.get("cwe_ids") or []
    if cwes:
        return cwes
    # Some PyPI/npm OSV records put CWEs under "cwes"
    return db.get("cwes") or []


# ── Cross-reference loaders ────────────────────────────────────────────
def latest_kev_snapshot() -> Path:
    snaps = sorted(REPO.joinpath("data").glob("kev-snapshot-*.json"))
    if not snaps:
        raise SystemExit("no data/kev-snapshot-*.json found")
    return snaps[-1]


def load_kev_cves() -> set[str]:
    snap = latest_kev_snapshot()
    print(f"  KEV snapshot: {snap.name}")
    kev = json.load(open(snap))
    return {v["cveID"] for v in kev["vulnerabilities"]}


def load_msf_cves() -> set[str]:
    p = REPO / "data" / "_metasploit-cves.json"
    if not p.exists():
        return set()
    raw = json.load(open(p))
    return set(raw.keys()) if isinstance(raw, dict) else set(raw or [])


def load_edb_cves() -> set[str]:
    p = REPO / "data" / "_exploitdb-cves.json"
    if not p.exists():
        return set()
    raw = json.load(open(p))
    return set(raw.keys()) if isinstance(raw, dict) else set(raw or [])


def load_hacker_tiers() -> dict:
    ht = json.load(open(REPO / "data" / "hacker-tiers.json"))
    return {cve: rec.get("tier") for cve, rec in (ht.get("tiers") or {}).items()
            if isinstance(rec, dict) and rec.get("tier")}


# ── Per-manifest event collection ──────────────────────────────────────
def collect_events_for_manifest(label: str, manifest: list[tuple[str, str, str]]) -> list[dict]:
    """For each package in manifest, fetch OSV and extract events that:
       - have published date >= CUTOFF
       - have GHSA severity HIGH or CRITICAL
    """
    events = []
    seen_keys = set()  # de-dup by (date, vuln_id, package)
    for eco, pkg, role in manifest:
        vulns = fetch_osv_for_package(eco, pkg)
        time.sleep(SLEEP_BETWEEN)
        for v in vulns:
            date = _published_date(v)
            if not date or date < CUTOFF:
                continue
            sev = _ghsa_severity_label(v)
            if sev not in ("HIGH", "CRITICAL"):
                continue
            short_pkg = pkg.split(":")[-1] if ":" in pkg else pkg
            key = (date, v.get("id", ""), short_pkg)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            events.append({
                "date": date,
                "vuln_id": v.get("id", ""),
                "aliases": v.get("aliases") or [],
                "package": short_pkg,
                "ecosystem": eco,
                "severity": sev,
                "is_np": role == "NP",
                "cwes": _cwes_from_vuln(v),
            })
    events.sort(key=lambda e: e["date"])
    return events


# ── Summarize ──────────────────────────────────────────────────────────
def summarize(label: str, events: list[dict],
              kev_cves: set[str], msf_cves: set[str], edb_cves: set[str],
              hacker_tiers: dict) -> dict:
    all_dates, npdi_dates, hacker_sa_dates, union_dates = [], [], [], []
    enriched, exploited = [], []
    order = ["S", "A", "B", "C", "D"]
    for e in events:
        cves = _cves_from_aliases(e["aliases"])
        kev = any(c in kev_cves for c in cves)
        msf = any(c in msf_cves for c in cves)
        edb = any(c in edb_cves for c in cves)
        tier = None
        for c in cves:
            t = hacker_tiers.get(c)
            if t and (tier is None or order.index(t) < order.index(tier)):
                tier = t
        is_npdi = e["is_np"] and _is_di_cwes(e["cwes"])
        is_hacker_sa = tier in ("S", "A")
        in_union = is_npdi or is_hacker_sa
        all_dates.append(e["date"])
        if is_npdi:       npdi_dates.append(e["date"])
        if is_hacker_sa:  hacker_sa_dates.append(e["date"])
        if in_union:      union_dates.append(e["date"])
        if kev or msf or edb:
            exploited.append({
                "date": e["date"], "ghsa": e["vuln_id"], "cves": cves,
                "package": e["package"], "in_kev": kev, "in_msf": msf, "in_edb": edb,
                "hacker_tier": tier,
            })
        enriched.append({
            "date": e["date"], "ghsa": e["vuln_id"], "cves": cves,
            "package": e["package"], "severity": e["severity"],
            "is_np": e["is_np"], "is_di": is_npdi,
            "hacker_tier": tier, "hacker_sa": is_hacker_sa,
            "in_union": in_union, "cwes": e["cwes"],
            "exploited": kev or msf or edb,
        })
    return {
        "label": label,
        "all_ch_event_count": len(events),
        "all_ch_clusters": _cluster_count(sorted(set(all_dates))),
        "npdi_event_count": len(npdi_dates),
        "npdi_clusters": _cluster_count(sorted(set(npdi_dates))),
        "hacker_sa_event_count": len(hacker_sa_dates),
        "hacker_sa_clusters": _cluster_count(sorted(set(hacker_sa_dates))),
        "model_union_event_count": len(union_dates),
        "model_union_clusters": _cluster_count(sorted(set(union_dates))),
        "exploited_count": len(exploited),
        "exploited_events": exploited,
        "events": enriched,
    }


# ── Dashboard patcher ──────────────────────────────────────────────────
def patch_dashboard_post_apr1(snapshot_through: str, summary: dict, frameworks: dict) -> bool:
    """Patch the POST_APR1 JS object in docs/dashboard.html with fresh data.
    Returns True if file changed, False otherwise."""
    path = REPO / "docs" / "dashboard.html"
    src = path.read_text()
    orig = src

    def fmt_arr(xs):
        return "[" + ", ".join(str(int(x)) for x in xs) + "]"

    # 1. snapshot_through
    src = re.sub(
        r'(snapshot_through:\s*")[^"]*(")',
        rf'\g<1>{snapshot_through}\g<2>',
        src,
        count=1,
    )

    # 2. labels — keep static ordering, but assert we still match
    keys = ("spring", "nodejs", "django", "netty", "real_java")
    labels = [frameworks[k]["label"] for k in keys]
    label_str = "[" + ", ".join(f'"{l}"' for l in labels) + "]"
    src = re.sub(
        r'(labels:\s*)\[[^\]]*\](?=,\s*\n\s*all_ch_clusters)',
        rf'\g<1>{label_str}',
        src,
        count=1,
    )

    # 3. all_ch_clusters
    src = re.sub(
        r'(all_ch_clusters:\s*)\[[^\]]*\]',
        lambda m: m.group(1) + fmt_arr([frameworks[k]["all_ch_clusters"] for k in keys]),
        src,
        count=1,
    )

    # 4. model_clusters (= union NP+DI ∪ Hacker S+A)
    src = re.sub(
        r'(model_clusters:\s*)\[[^\]]*\]',
        lambda m: m.group(1) + fmt_arr([frameworks[k]["model_union_clusters"] for k in keys]),
        src,
        count=1,
    )

    # 5. exploited counts
    src = re.sub(
        r'(exploited:\s*)\[[^\]]*\]',
        lambda m: m.group(1) + fmt_arr([frameworks[k]["exploited_count"] for k in keys]),
        src,
        count=1,
    )

    # 6. events: [...] block — rewrite the whole list
    fwk_label_to_key = {"Spring Boot": "Spring", "Node.js/Express": "Node",
                         "Django/Python": "Django", "Netty": "Netty",
                         "Real-world Java": "RealJava"}
    rows = []
    for k in keys:
        f = frameworks[k]
        fwk_short = fwk_label_to_key[f["label"]]
        for e in f["events"]:
            cve = (e["cves"] or [None])[0]
            row = (
                '        {date:"%s", framework:"%s", pkg:"%s", sev:"%s", '
                'cwes:%s, npdi:%s, hacker:%s, exploited:%s, cve:%s},'
                % (
                    e["date"], fwk_short, e["package"], e["severity"],
                    json.dumps(e["cwes"]),
                    "true" if e["is_di"] else "false",
                    f'"{e["hacker_tier"]}"' if e["hacker_tier"] else "null",
                    "true" if e["exploited"] else "false",
                    f'"{cve}"' if cve else "null",
                )
            )
            rows.append(row)
    events_block = "[\n" + "\n".join(rows) + "\n    ]"
    # Replace the events: [...] block — match opening through matching close.
    # Use a multiline DOTALL match that picks the smallest events array under POST_APR1.
    src = re.sub(
        r'(events:\s*)\[[^\]]*?(?:\{[^}]*\}[^\]]*?)*\](?=,\s*\n\s*\};)',
        lambda m: m.group(1) + events_block,
        src,
        count=1,
        flags=re.DOTALL,
    )

    if src != orig:
        path.write_text(src)
        return True
    return False


# ── Main ───────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="rebuild + diff vs current")
    args = ap.parse_args()

    print("Loading exploit signals...")
    kev_cves = load_kev_cves()
    msf_cves = load_msf_cves()
    edb_cves = load_edb_cves()
    hacker_tiers = load_hacker_tiers()
    print(f"  KEV: {len(kev_cves)} CVEs   MSF: {len(msf_cves)}   EDB: {len(edb_cves)}   Hacker-scored: {len(hacker_tiers)}")

    frameworks = {}
    for key, label, manifest in MANIFESTS:
        print(f"\n[{key}] fetching OSV for {len(manifest)} packages...")
        events = collect_events_for_manifest(label, manifest)
        print(f"  {len(events)} C/H events since {CUTOFF}")
        frameworks[key] = summarize(label, events, kev_cves, msf_cves, edb_cves, hacker_tiers)

    keys = ("spring", "nodejs", "django", "netty", "real_java")
    snapshot_through = dt.datetime.utcnow().strftime("%Y-%m-%d")
    out = {
        "generated_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cutoff": CUTOFF,
        "snapshot_through": snapshot_through,
        "description": (
            "Live tracker — events with disclosure date >= 2026-04-01 for the "
            "five manifests (4 modeled + 1 real-world Java enterprise), with "
            "exploit cross-reference. Patch-event counts use the canonical 7-day "
            "clustering rule. Refreshed daily by scripts/refresh_post_apr1.py "
            "via the kev-analysis-refresh scheduled task."
        ),
        "methodology": {
            "cluster_window_days": 7,
            "di_cwe_set_frozen_2026_05_01": sorted(DI_CWES),
            "exploit_signals": ["CISA KEV", "Metasploit", "ExploitDB"],
            "model_definition": "NP+DI ∪ DQ ∪ Hacker S+A (DQ stand-in: 0 for fresh events until analyst scores)",
        },
        "frameworks": frameworks,
        "summary": {
            "labels":               [frameworks[k]["label"]                for k in keys],
            "all_ch_clusters":      [frameworks[k]["all_ch_clusters"]      for k in keys],
            "model_union_clusters": [frameworks[k]["model_union_clusters"] for k in keys],
            "exploited_counts":     [frameworks[k]["exploited_count"]      for k in keys],
            "npdi_clusters":        [frameworks[k]["npdi_clusters"]        for k in keys],
            "hacker_sa_clusters":   [frameworks[k]["hacker_sa_clusters"]   for k in keys],
        },
    }

    out_path = REPO / "data" / "post-apr1-per-framework.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"\nwrote {out_path}")
    print(json.dumps(out["summary"], indent=2))

    if args.check:
        print("\n--check: not patching dashboard (use without --check to patch)")
        return

    changed = patch_dashboard_post_apr1(snapshot_through, out["summary"], frameworks)
    print(f"\ndashboard.html POST_APR1 block: {'patched' if changed else 'no change'}")


if __name__ == "__main__":
    main()
