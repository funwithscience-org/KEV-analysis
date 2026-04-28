#!/usr/bin/env python3
"""
Build the evergreen Java generation-mapping file for the
`docs/evergreen.html` Java section, and emit the tallies the page prose
references.

The "evergreen question" is, for each CVE in the canonical 7-year manifest:
if a team had aggressively upgraded (Java 8 -> 11/17/21, Spring 5 ->
Spring 6 / Spring Boot 3, Tomcat 9 -> 10.x/11) instead of staying on the
old generation, would they have AVOIDED the CVE, would the upgrade have
INTRODUCED the CVE, or would the CVE affect BOTH generations equally?

Categories per CVE:
  - "avoids"       : CVE only affects the old generation; the new gen is
                     not vulnerable. Evergreening removes the bug.
  - "makes_worse"  : CVE only affects the new generation; the old gen
                     was immune. Evergreening introduced the bug.
  - "no_difference": CVE affects both generations equally (shared-code
                     bugs, e.g. Tomcat request smuggling, Log4Shell).
                     Evergreening does NOT change CVE exposure; only
                     patch-currency does.
  - "irrelevant"   : The package has no Spring/Java-generation axis at
                     all - it's an application-level dep (XStream,
                     SnakeYAML, Hazelcast) or a transitive whose version
                     is selected independently of Spring. Evergreening
                     can't help; only dependency-pruning or patch
                     currency can.

The headline outcome the page reports is computed from the NP+DI raw
subset (40 events) - the events the structure test would flag for
emergency rebuilds. That's the cohort where evergreening matters
operationally; the rest of the manifest is either lower-stakes patch
currency (un-flagged-by-NP+DI) or noise.

Note on `irrelevant` vs `no_difference`:
  - `no_difference` is reserved for packages whose CVE history IS tied
    to the Spring/Java generation but where this particular CVE happens
    to affect both old and new generations of that package (e.g. Tomcat
    8.5/9 AND 10.x). This is most of the manifest.
  - `irrelevant` is reserved for packages that sit *outside* the
    generation axis entirely - XStream, SnakeYAML, jackson-databind,
    Hazelcast, ActiveMQ, etc. You don't get a different version of
    these by upgrading Java or Spring; you get them by managing
    transitive deps yourself.

The line between the two is judgment, but the operational point holds:
neither category is helped by the generation-shift lever the page is
testing. Both are "evergreening doesn't help; do something else."

Re-derive: `python3 scripts/build_evergreen_java.py`
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EVENTS_FILE = REPO / "data" / "seven-year-manifest-events.json"
MAPPING_FILE = REPO / "data" / "evergreen-generation-mapping.json"

DQ_RESCUE_CVES = {"CVE-2020-1938", "CVE-2025-24813", "CVE-2026-34197"}


def package_family(pkgs: list[str]) -> str:
    if not pkgs:
        return "unknown"
    short = pkgs[0].split(":")[-1]
    if "tomcat" in short:
        return "tomcat"
    if "xstream" in short:
        return "xstream"
    if "log4j" in short:
        return "log4j"
    if "jackson" in short:
        return "jackson"
    if "spring-security" in short:
        return "spring-security"
    if short.startswith("spring-") or "spring-boot" in short:
        return "spring-framework-boot"
    if "thymeleaf" in short:
        return "thymeleaf"
    if "activemq" in short:
        return "activemq"
    if short.startswith("mina"):
        return "mina"
    if "sshd" in short:
        return "sshd"
    if "cxf" in short:
        return "cxf"
    if "hazelcast" in short:
        return "hazelcast"
    if "snakeyaml" in short:
        return "snakeyaml"
    if "commons-text" in short:
        return "commons-text"
    if "commons-io" in short:
        return "commons-io"
    if "logback" in short:
        return "logback"
    if "postgresql" in short:
        return "postgresql"
    if "httpclient" in short:
        return "httpclient"
    return f"?{short}"


# -------------------------------------------------------------------------
# Per-CVE manual classifications.
#
# Only CVEs whose generation-mapping is NOT the family default get an
# entry here. Defaults are applied in classify_event() below.
# -------------------------------------------------------------------------
MANUAL_CLASSIFICATIONS: dict[str, dict] = {
    # --- "Makes worse": evergreening introduced the bug ---
    "CVE-2022-22965": {
        "evergreen_category": "makes_worse",
        "old_gen_affected": [],
        "new_gen_affected": ["Spring 5.2.x/5.3.x on JDK 9+", "Spring 6.0.x on JDK 17+"],
        "rationale": (
            "Spring4Shell. Requires JDK 9+ to exploit via the "
            "Class.getModule() chain. Java 8 stacks (running Spring 4.x "
            "or even Spring 5.x on JDK 8) were completely immune. The "
            "evergreen path (Java 11/17 + Spring 5.3+) was the "
            "vulnerable path. KEV + Metasploit confirmed exploited."
        ),
    },
    "CVE-2026-34197": {
        "evergreen_category": "makes_worse",
        "old_gen_affected": [],
        "new_gen_affected": ["ActiveMQ 6.0.0-6.2.2 (default Jolokia auth removed)"],
        "rationale": (
            "ActiveMQ 6.0.0-6.1.1 removed default Jolokia authentication "
            "(CVE-2024-32114), making the new 6.x generation more "
            "exploitable than 5.x until 6.2.3 patched it. KEV-listed. "
            "An old-gen ActiveMQ 5.x team was protected by default."
        ),
    },

    # --- "Avoids": dead/abandoned libraries dropped during a generation shift ---
    # Note: the prior page narrative cited CVE-2019-10172 (jackson-mapper-asl)
    # and CVE-2019-17495 (Swagger UI / Springfox) as the two "avoided" events.
    # Neither appears in the canonical 58-pkg manifest because jackson-mapper-asl
    # (Jackson 1.x) and Springfox are not in the runtime portfolio - the
    # canonical manifest is built around the live (Jackson 2.x / springdoc)
    # stack, so those packages have no events in the events file. The
    # "evergreening avoids" set on the canonical manifest is therefore
    # *empty* - a directional shift from the prior 2/2 framing. Documented
    # honestly in the page prose.

    # --- DQ-rescue events: their generation status is real but they are
    # not NP+DI raw, so they don't sit in the "evergreening flagged a
    # rebuild" set. Classify them honestly anyway since the prose still
    # discusses Ghostcat, Tomcat partial-PUT, and ActiveMQ Jolokia. ---
    "CVE-2020-1938": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 7.x/8.5.x/9.x"],
        "new_gen_affected": ["AJP enabled by default in 7/8.5/9; 10+ disables AJP by default"],
        "rationale": (
            "Ghostcat. Affects all Tomcat generations that ship AJP "
            "enabled by default. Tomcat 10+ disabled AJP by default but "
            "the underlying CVE still applies if you re-enable it - the "
            "shared connector code is the same. Patch currency (8.5.51+ / "
            "9.0.31+) closes it without an evergreen jump."
        ),
    },
    "CVE-2025-24813": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 9.x"],
        "new_gen_affected": ["Tomcat 10.1.x", "Tomcat 11.x"],
        "rationale": (
            "Tomcat partial-PUT RCE. Affected 9.0.x AND 10.1.x AND "
            "11.0.x simultaneously - the partial-PUT request handling "
            "code is shared across generations. Patch currency on any "
            "generation closes it; evergreening neither helps nor hurts."
        ),
    },

    # --- Spring 4-vs-5 generation question for the 4 NP+DI Spring Security
    # auth-bypass events. The user is asking "if I had stayed on Spring 4
    # instead of moving to Spring 5/6, would I have avoided this?" - and
    # for these the answer is "no", because the bugs are in code paths
    # that exist in both 4.x and 5.x/6.x security cores. Spring 4.x
    # itself is EOL well before these landed (most of these are 2024+
    # disclosures), so the evergreen counterfactual is "stayed on Spring 5"
    # vs "moved to Spring 6". Both 5 and 6 are affected. ---
    "CVE-2025-41248": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.x", "Spring Security 6.x"],
        "new_gen_affected": ["Spring Security 7.0.0-M1"],
        "rationale": (
            "Authorization bypass via annotation detection. Affects all "
            "supported Spring Security 5.x and 6.x lines (and the 7.0 "
            "M1 milestone). Fixed by patch release, not generation."
        ),
    },
    "CVE-2025-41232": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.x", "Spring Security 6.x"],
        "new_gen_affected": ["Spring Security 6.x"],
        "rationale": (
            "Authorization bypass for method security on private methods. "
            "Affects 5.x and 6.x equally - shared annotation processor."
        ),
    },
    "CVE-2024-22257": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.7.x-5.8.x", "Spring Security 6.x"],
        "new_gen_affected": ["Spring Security 6.x"],
        "rationale": (
            "Erroneous authentication pass with AuthenticatedVoter. "
            "Affects 5.7+/5.8.x AND 6.0/6.1/6.2. Shared core."
        ),
    },
    "CVE-2022-31692": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.x"],
        "new_gen_affected": ["Spring Security 5.7+ / 6.0"],
        "rationale": (
            "forward/include dispatcher bypass. Affects 5.x and the then-"
            "current 5.7/6.0 lines. Not generation-axis."
        ),
    },
    "CVE-2022-22978": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.5.x/5.6.x"],
        "new_gen_affected": ["Spring Security 5.5.x/5.6.x"],
        "rationale": (
            "RegexRequestMatcher authorization bypass. The 5.x line is "
            "the only one that exists at disclosure time; 6.0 wasn't "
            "released until November 2022. Not a generation-axis question."
        ),
    },
    "CVE-2021-22119": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 5.5.x and earlier"],
        "new_gen_affected": ["Spring Security 5.5.x and earlier"],
        "rationale": "Affects all 5.x at disclosure. No 6.x exists yet.",
    },
    "CVE-2019-11272": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security 4.2.x", "Spring Security 5.0.x/5.1.x"],
        "new_gen_affected": ["Spring Security 5.0.x/5.1.x"],
        "rationale": "Affects 4.x AND 5.x security-core. Shared password handling.",
    },
    "CVE-2018-15801": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Security OAuth 2.3.x"],
        "new_gen_affected": ["Spring Security OAuth 2.3.x"],
        "rationale": "OAuth library predates the 5/6 generation axis.",
    },

    # --- Spring Framework webmvc path-traversal pair (post-5.3-EOL) ---
    # Affects 5.3.x AND 6.x; the OSS-vs-paywalled axis matters but the
    # vulnerability axis does not.
    "CVE-2024-38816": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Framework 5.3.x (commercial-only fix)"],
        "new_gen_affected": ["Spring Framework 6.0.x/6.1.x"],
        "rationale": (
            "Path traversal in functional web frameworks. Affects 5.3 "
            "AND 6.x. Free patch only on 6.x (5.3.x post-EOL needs "
            "Broadcom commercial subscription). No evergreen avoidance, "
            "but evergreening preserves free-patch access."
        ),
    },
    "CVE-2024-38819": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Spring Framework 5.3.x (commercial-only fix)"],
        "new_gen_affected": ["Spring Framework 6.0.x/6.1.x"],
        "rationale": (
            "Path traversal in static-resource handling. Affects 5.3 "
            "AND 6.x. Same paywall pattern as CVE-2024-38816."
        ),
    },

    # --- Tomcat NP+DI events (the 7 "Tomcat all-gens" events the prose discusses) ---
    # All of these affect 8.5/9 AND 10.1/11 simultaneously.
    "CVE-2019-0232": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 7.x/8.5.x/9.x (Windows only)"],
        "new_gen_affected": ["Tomcat 10.x didn't exist at disclosure (April 2019)"],
        "rationale": (
            "Windows-only CGI command injection. Affected the 7/8.5/9 "
            "lines that existed at disclosure. Tomcat 10.0.0 wasn't "
            "released until December 2020 (>1.5y later). The fix "
            "(7.0.94 / 8.5.40 / 9.0.19) was a same-day point release - "
            "evergreening within a generation handled it. KEV-listed via "
            "MSF/EDB. Not a generation-axis bug."
        ),
    },
    "CVE-2026-29145": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 9.x"],
        "new_gen_affected": ["Tomcat 10.1.x", "Tomcat 11.x"],
        "rationale": "CLIENT_CERT auth failure logic shared across 9/10.1/11.",
    },
    "CVE-2026-34483": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 9.x"],
        "new_gen_affected": ["Tomcat 10.1.x", "Tomcat 11.x"],
        "rationale": "JsonAccessLogValve escaping bug; shared code.",
    },
    "CVE-2025-55752": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 9.x"],
        "new_gen_affected": ["Tomcat 10.1.x", "Tomcat 11.x"],
        "rationale": "Relative path traversal across all current generations.",
    },
    "CVE-2023-46589": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 8.5.x/9.x"],
        "new_gen_affected": ["Tomcat 10.1.x/11.x"],
        "rationale": "HTTP/1.1 header smuggling; shared connector code.",
    },
    "CVE-2022-45143": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 8.5.x/9.x"],
        "new_gen_affected": ["Tomcat 10.0.x/10.1.x"],
        "rationale": "JsonErrorReportValve escaping; shared error-reporter code.",
    },
    "CVE-2022-42252": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["Tomcat 8.5.x/9.x"],
        "new_gen_affected": ["Tomcat 10.0.x/10.1.x"],
        "rationale": "Content-Length header validation; shared code.",
    },

    # --- Log4j (the headline shared-code bug) ---
    "CVE-2021-44228": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["log4j-core 2.0-beta9 - 2.14.1"],
        "new_gen_affected": ["log4j-core 2.0-beta9 - 2.14.1"],
        "rationale": (
            "Log4Shell. Affected log4j-core regardless of Spring/Java "
            "version. Spring Boot defaults to Logback, but if you opted "
            "into log4j2, both old and new Spring Boot generations were "
            "equally vulnerable. KEV + MSF + EDB confirmed exploited."
        ),
    },
    "CVE-2021-45046": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["log4j-core 2.0 - 2.15.0"],
        "new_gen_affected": ["log4j-core 2.0 - 2.15.0"],
        "rationale": "Incomplete fix for Log4Shell; same generation-agnostic story.",
    },

    # --- Thymeleaf 2026 pair: thymeleaf 3.1.x AND thymeleaf-spring6 ---
    "CVE-2026-40477": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["thymeleaf 3.1.x with Spring 5"],
        "new_gen_affected": ["thymeleaf 3.1.x with Spring 6 (thymeleaf-spring6)"],
        "rationale": (
            "Expression scope bug affects the core thymeleaf 3.1.x + "
            "the thymeleaf-spring6 binding. Both old (5) and new (6) "
            "Spring generations are affected via the matching binding."
        ),
    },
    "CVE-2026-40478": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["thymeleaf 3.1.x with Spring 5"],
        "new_gen_affected": ["thymeleaf 3.1.x with Spring 6 (thymeleaf-spring6)"],
        "rationale": "Same shared-template-engine pattern as CVE-2026-40477.",
    },

    # --- The 3 CXF NP+DI events ---
    "CVE-2022-46364": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["CXF 3.4.x/3.5.x"],
        "new_gen_affected": ["CXF 3.5.x/3.6.x/4.0.x"],
        "rationale": "SSRF in MTOM attachment handling; shared across major lines.",
    },
    "CVE-2021-22696": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["CXF 3.4.x"],
        "new_gen_affected": ["CXF 3.4.x"],
        "rationale": "OAuth2 DoS; affects all 3.4.x at disclosure.",
    },
    "CVE-2019-12419": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["CXF 3.2.x/3.3.x"],
        "new_gen_affected": ["CXF 3.2.x/3.3.x"],
        "rationale": "OIDC session hijack; affects all then-current minor lines.",
    },

    # --- ActiveMQ Jolokia auth (NP+DI raw): the only NP+DI activemq event ---
    "CVE-2019-0222": {
        "evergreen_category": "no_difference",
        "old_gen_affected": ["ActiveMQ 5.15.x"],
        "new_gen_affected": ["ActiveMQ 5.15.x"],
        "rationale": "OpenWire deserialization; pre-6.x, no generation axis.",
    },

    # --- Hazelcast NP+DI events ---
    # Hazelcast is a runtime dep that doesn't track Spring/Java generation.
    # Mark irrelevant for the structural question.
    "CVE-2023-45860": {
        "evergreen_category": "irrelevant",
        "old_gen_affected": ["Hazelcast Platform 5.x"],
        "new_gen_affected": ["Hazelcast Platform 5.x"],
        "rationale": (
            "Hazelcast is a standalone runtime dep. Its version is "
            "selected independently of Spring/Java generation - "
            "evergreening Spring or Java doesn't change which "
            "Hazelcast you run."
        ),
    },
    "CVE-2022-0265": {
        "evergreen_category": "irrelevant",
        "old_gen_affected": ["Hazelcast 4.x/5.x"],
        "new_gen_affected": ["Hazelcast 4.x/5.x"],
        "rationale": "XXE in config parser. Hazelcast version is independent of Spring/Java gen.",
    },

    # --- MINA NP+DI ---
    "CVE-2024-52046": {
        "evergreen_category": "irrelevant",
        "old_gen_affected": ["MINA 2.0.x/2.1.x/2.2.x"],
        "new_gen_affected": ["MINA 2.0.x/2.1.x/2.2.x"],
        "rationale": (
            "MINA is an app-level networking framework. Pinned in the "
            "manifest independently of Spring/Java generation. "
            "Dependency-pruning or patch currency, not evergreening."
        ),
    },
}


def default_classification(family: str, cve: str, summary: str) -> dict:
    """
    Default per-family classification used when MANUAL_CLASSIFICATIONS
    has no entry for a CVE. Keep these conservative - only mark
    generations affected if the family is genuinely on the
    Java/Spring/Tomcat generation axis.
    """
    if family == "tomcat":
        # Tomcat events with no manual entry: default to no_difference
        # because Tomcat's request-handling code is overwhelmingly
        # shared across 8.5/9/10/11 generations. This is a conservative
        # default that matches the 7-Tomcat-CVEs-all-affect-all-gens
        # pattern documented in the existing prose.
        return {
            "evergreen_category": "no_difference",
            "old_gen_affected": ["Tomcat 8.5.x/9.x"],
            "new_gen_affected": ["Tomcat 10.x/11.x"],
            "rationale": "Default: Tomcat shared-code bug. See per-CVE NVD CPE for ranges.",
        }
    if family == "xstream":
        # XStream is an application-level dependency. Its version is
        # selected independently of Spring/Java generation. Mark
        # irrelevant.
        return {
            "evergreen_category": "irrelevant",
            "old_gen_affected": [],
            "new_gen_affected": [],
            "rationale": "XStream is an app-level dep; no Spring/Java gen axis. Drop or pin to 1.4.18+.",
        }
    if family == "log4j":
        return {
            "evergreen_category": "no_difference",
            "old_gen_affected": ["log4j-core 2.x"],
            "new_gen_affected": ["log4j-core 2.x"],
            "rationale": "log4j-core 2.x line; same library across all Java/Spring versions.",
        }
    if family == "jackson":
        # jackson-databind is a transitive dep (or direct) whose
        # version is pinned independently of Spring/Java generation.
        # Treat as irrelevant.
        return {
            "evergreen_category": "irrelevant",
            "old_gen_affected": [],
            "new_gen_affected": [],
            "rationale": (
                "jackson-databind 2.x is the same library across Spring "
                "Boot 2 and 3. CVE applies by jackson version, not "
                "generation. Patch-currency on jackson, not evergreening."
            ),
        }
    if family == "spring-framework-boot":
        return {
            "evergreen_category": "no_difference",
            "old_gen_affected": ["Spring 5.x / Spring Boot 2.x"],
            "new_gen_affected": ["Spring 6.x / Spring Boot 3.x"],
            "rationale": "Default: Spring/Boot shared-code bug across 5/6 lines.",
        }
    if family == "spring-security":
        return {
            "evergreen_category": "no_difference",
            "old_gen_affected": ["Spring Security 5.x"],
            "new_gen_affected": ["Spring Security 6.x"],
            "rationale": "Default: Spring Security shared-code bug across 5/6 lines.",
        }
    if family in ("activemq", "snakeyaml", "commons-text", "commons-io",
                  "logback", "postgresql", "httpclient", "hazelcast",
                  "mina", "sshd", "thymeleaf", "cxf"):
        return {
            "evergreen_category": "irrelevant",
            "old_gen_affected": [],
            "new_gen_affected": [],
            "rationale": (
                f"{family} version is selected independently of "
                "Spring/Java generation. Patch-currency on the dep, "
                "not evergreening."
            ),
        }
    return {
        "evergreen_category": "irrelevant",
        "old_gen_affected": [],
        "new_gen_affected": [],
        "rationale": "Default: version axis unclear, treat as not in evergreen scope.",
    }


def classify_event(e: dict) -> dict:
    cve = e["cve"]
    if cve in MANUAL_CLASSIFICATIONS:
        m = MANUAL_CLASSIFICATIONS[cve]
        out = {
            "package": (e.get("packages") or ["unknown"])[0].split(":")[-1],
            "evergreen_category": m["evergreen_category"],
            "old_gen_affected": m.get("old_gen_affected", []),
            "new_gen_affected": m.get("new_gen_affected", []),
            "rationale": m["rationale"],
        }
        return out
    fam = package_family(e.get("packages", []))
    d = default_classification(fam, cve, e.get("summary", ""))
    return {
        "package": (e.get("packages") or ["unknown"])[0].split(":")[-1],
        "evergreen_category": d["evergreen_category"],
        "old_gen_affected": d.get("old_gen_affected", []),
        "new_gen_affected": d.get("new_gen_affected", []),
        "rationale": d["rationale"],
    }


def build_mapping() -> dict:
    events = json.load(open(EVENTS_FILE))["events"]
    mapping = {}
    for e in events:
        mapping[e["cve"]] = classify_event(e)
    return mapping


def tally(events: list[dict], mapping: dict) -> dict:
    """Compute the headline tallies for the page."""
    npdi_raw = [e for e in events if e.get("is_np") and e.get("is_di")]
    exploited = [e for e in events if e.get("exploited")]

    def cat_count(subset, cat):
        return sum(1 for e in subset if mapping[e["cve"]]["evergreen_category"] == cat)

    # Per-family tallies on NP+DI raw set
    fam_counts_npdi: Counter = Counter()
    for e in npdi_raw:
        fam_counts_npdi[package_family(e.get("packages", []))] += 1

    # Per-family tallies on full 194
    fam_counts_all: Counter = Counter()
    for e in events:
        fam_counts_all[package_family(e.get("packages", []))] += 1

    # Cross-tab: avoids vs exploited; makes_worse vs exploited
    avoids_exploited = [e for e in events if mapping[e["cve"]]["evergreen_category"] == "avoids" and e.get("exploited")]
    makes_worse_exploited = [e for e in events if mapping[e["cve"]]["evergreen_category"] == "makes_worse" and e.get("exploited")]

    avoids_in_npdi = cat_count(npdi_raw, "avoids")
    worse_in_npdi = cat_count(npdi_raw, "makes_worse")
    nodiff_in_npdi = cat_count(npdi_raw, "no_difference")
    irrelevant_in_npdi = cat_count(npdi_raw, "irrelevant")

    return {
        "totals": {
            "all_ch": len(events),
            "npdi_raw": len(npdi_raw),
            "exploited": len(exploited),
        },
        "evergreen_on_npdi_raw": {
            "avoids": avoids_in_npdi,
            "makes_worse": worse_in_npdi,
            "no_difference": nodiff_in_npdi,
            "irrelevant": irrelevant_in_npdi,
        },
        "evergreen_on_all": {
            "avoids": cat_count(events, "avoids"),
            "makes_worse": cat_count(events, "makes_worse"),
            "no_difference": cat_count(events, "no_difference"),
            "irrelevant": cat_count(events, "irrelevant"),
        },
        "exploited_cross_tab": {
            "avoids_and_exploited": [e["cve"] for e in avoids_exploited],
            "makes_worse_and_exploited": [e["cve"] for e in makes_worse_exploited],
        },
        "per_family_npdi_raw": dict(fam_counts_npdi.most_common()),
        "per_family_all_ch": dict(fam_counts_all.most_common()),
    }


def write_mapping(mapping: dict) -> None:
    payload = {
        "description": (
            "Per-CVE evergreen-generation mapping for the "
            "docs/evergreen.html Java section. Built by "
            "scripts/build_evergreen_java.py from "
            "data/seven-year-manifest-events.json. The "
            "evergreen_category answers: did upgrading from the "
            "old Java/Spring/Tomcat generation to the new one help "
            "(avoids), hurt (makes_worse), make no difference "
            "(no_difference), or fall outside the generation axis "
            "entirely (irrelevant)?"
        ),
        "categories": {
            "avoids": "CVE only affects the old generation; new gen is not vulnerable.",
            "makes_worse": "CVE only affects the new generation; old gen was immune.",
            "no_difference": "CVE affects both old and new generations equally.",
            "irrelevant": "Package has no Spring/Java generation axis (app-level dep).",
        },
        "evergreen_old_gen": "Java 8 + Spring 5 + Spring Boot 2.x + Tomcat 8.5/9",
        "evergreen_new_gen": "Java 17/21 + Spring 6 + Spring Boot 3 + Tomcat 10.x/11",
        "scope_note": (
            "Mapping covers all 194 events in the canonical 58-pkg "
            "manifest. The evergreen.html Java section's headline tallies "
            "are computed against the NP+DI raw subset (40 events) - "
            "the events the structure test would flag for emergency "
            "rebuilds. Other categories (no_difference, irrelevant) on "
            "the wider 194 are reported in the breakdown but not in the "
            "headline."
        ),
        "input_source": "data/seven-year-manifest-events.json",
        "mapping": mapping,
    }
    MAPPING_FILE.write_text(json.dumps(payload, indent=2) + "\n")


def main() -> int:
    check_only = "--check" in sys.argv
    events = json.load(open(EVENTS_FILE))["events"]
    mapping = build_mapping()

    if check_only:
        if not MAPPING_FILE.exists():
            print(f"FAIL: {MAPPING_FILE} does not exist.")
            return 1
        existing = json.load(open(MAPPING_FILE))["mapping"]
        if existing != mapping:
            print("FAIL: mapping is stale; re-run scripts/build_evergreen_java.py")
            return 1
        # And every event has an entry
        missing = [e["cve"] for e in events if e["cve"] not in mapping]
        if missing:
            print(f"FAIL: {len(missing)} events missing mapping: {missing[:5]}")
            return 1
        print("OK: mapping is reproducible and complete.")
        return 0

    write_mapping(mapping)
    t = tally(events, mapping)
    print(json.dumps(t, indent=2))
    print(f"Wrote {MAPPING_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
