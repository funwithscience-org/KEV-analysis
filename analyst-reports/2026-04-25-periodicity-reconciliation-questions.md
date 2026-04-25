# Periodicity 7-Year Backtest — Reconciliation Questions

**Date:** 2026-04-25
**Author:** Claude (current session, working with steve)
**Audience:** The prior AI that authored docs/periodicity.html and the canonical NP+DI table
**Purpose:** Reconcile the doc's empirical claims against a reproduced dataset built from the cached and live OSV/KEV inputs

---

## Background

The user asked us to test a hypothesis: *within NP+DI, can we identify characteristics that predict actual exploitation, splitting NP+DI into NP+DI/high vs NP+DI/low?* In the course of that work we tried to reproduce the doc's 7-year backtest from the underlying data. We hit several reconciliation issues that we'd like to resolve before publishing any refinement.

The doc's load-bearing claim is in the periodicity page's "Methodology Stress Test" section:

> "NP+DI catches 5 of 8 in-scope exploited CVEs. The 3 misses are all CWE misclassification on network parsers (Ghostcat, Tomcat PUT, ActiveMQ). Two additional exploited CVEs (commons-text, SnakeYAML) are out of NP+DI's scope entirely."

The corresponding tables are in `docs/periodicity.html` lines ~322-356 (the 30-event NP+DI list) and ~359-366 (the 3-event misses table). We extracted both into `data/doc-canonical-npdi-events.json` and cross-referenced against:

- `data/kev-snapshot-2026-04-23.json` — CISA KEV catalog snapshot
- `data/_metasploit-cves.json` — full Metasploit module CVE list (3,108 CVEs from rapid7/metasploit-framework `modules_metadata_base.json`)
- `data/_exploitdb-cves.json` — full ExploitDB CVE list (24,941 CVEs from gitlab.com/exploit-database `files_exploits.csv`)
- `data/_manifest-osv-cache.json` — live OSV API query results for 54 Maven packages (the script's 48 + log4j-core, log4j-api, xstream, activemq trio added to align with the doc)
- `analysis-scripts/spring_manifest_analysis.py` — the manifest definition

This document lists the specific things we couldn't reconcile. We're trying to understand whether each is a doc error, a data drift, or a methodology choice we don't yet have visibility into.

---

## 1. Manifest scope: 48 vs 60 vs broader

### What we observe

The doc text describes the analysis as running against "a real enterprise Java manifest (60 libraries)". The Python script `spring_manifest_analysis.py` defines a `MANIFEST` of 48 Maven packages.

When we extract every package mentioned in the doc's NP+DI table (`docs/periodicity.html` lines 322-356) and cross-reference against the script's manifest, we find these packages **referenced in the doc's table but not in the script's manifest**:

| Package | Doc's CVEs against it | In script's MANIFEST? |
|---|---|---|
| `dom4j` | CVE-2018-1000632, CVE-2020-10683 | No |
| `spring-messaging` | CVE-2018-1275, CVE-2018-1270 | No |
| `Swagger UI` | CVE-2019-17495 | No |
| `jackson-mapper-asl` | CVE-2019-10172 | No (jackson-databind is, but not the older Jackson 1.x) |
| `Spring Expression` | CVE-2023-20863 | No (only via spring-core transitive) |
| `Hazelcast` | CVE-2023-45860 | No |
| `Apache CXF` | CVE-2024-28752 | No |
| `Apache MINA` | CVE-2024-52046 | No |
| `Log4j` (log4j-core) | CVE-2021-44228, CVE-2021-45046 | No (Spring Boot uses logback by default) |
| `XStream` | 7 CVEs in doc's table | No |
| `ActiveMQ` | CVE-2026-34197 (in misses table) | No (RabbitMQ is in the manifest, not ActiveMQ) |

That's 11+ packages the doc analyzes that aren't in the script manifest. The doc's "60 libraries" is roughly the script's 48 + this additional set.

### Question 1a

**Where is the actual 60-library manifest defined?** The script defines 48; the doc analyzes a superset. Is there a different manifest file we should be looking at, or were the additional packages added on the fly during the analysis without being checked in?

### Question 1b

**For each "extra" package, what was the rationale?**
- `log4j-core`, `xstream`, `activemq-*` are not Spring Boot defaults — they only enter via specific starters (`spring-boot-starter-log4j2`, `spring-boot-starter-activemq`) or explicit dependencies. Were these added because they're "commonly seen" or because they were in a specific real-world manifest that informed the analysis?
- `Swagger UI`, `Hazelcast`, `Apache CXF`, `Apache MINA` are even further from default Spring Boot. What's the inclusion criterion?
- `dom4j`, `jackson-mapper-asl`, `spring-messaging` are arguably defaults or near-defaults in some Spring shapes — but the script's MANIFEST excludes them. Intentional?

### Why this matters

The "8 in-scope exploited CVEs" headline depends on which packages count as in-scope. With the script's 48-package manifest strictly enforced, we count 5 in-scope exploited (Spring4Shell, Log4Shell ×2, XStream RCE if you accept xstream as in-scope, Tomcat partial PUT 2025) — different number, different denominator, different headline rate.

---

## 2. ActiveMQ specifically

### What we observe

The doc's misses table at line 364 includes:

> CVE-2026-34197 — ActiveMQ (Jolokia) — CWE-20 — generic; should be CWE-94 code injection — KEV

ActiveMQ is not in the script's manifest. It is not a transitive dependency of `spring-amqp` or `amqp-client` (those are RabbitMQ-specific). It would only be present if the app explicitly depends on `spring-boot-starter-activemq` or `org.apache.activemq:activemq-{broker,client,all}`.

### Question 2

**Is ActiveMQ assumed to be in scope for this analysis?**

If yes, what's the assumption — "typical enterprise Spring Boot app uses ActiveMQ for messaging"? If so, the manifest should reflect that explicitly (and so should the doc's claim about which manifest is being analyzed).

If no, the misses table should drop CVE-2026-34197, and the headline becomes "5 caught + 2 missed = 7 in-scope exploited" rather than 5+3=8.

---

## 3. Text4Shell and SnakeYAML "out of scope" claim

### What we observe

The doc's prose at line ~316 says:

> "Two additional exploited CVEs (commons-text, SnakeYAML) are out of NP+DI's scope entirely."

We checked our CISA KEV snapshot (data/kev-snapshot-2026-04-23.json, catalog version 2026.04.23):
- **CVE-2022-42889 (Text4Shell, commons-text)**: NOT in KEV
- **CVE-2022-1471 (SnakeYAML)**: NOT in KEV

Both are in Metasploit. Neither is in CISA KEV (currently or, per a quick web check, historically — though we'd want you to confirm this).

### Question 3

**What's the doc's definition of "exploited" for these two CVEs?**

- If "exploited" = CISA KEV only: the claim seems inconsistent because neither Text4Shell nor SnakeYAML is in KEV. They shouldn't be in the "exploited" set at all.
- If "exploited" = CISA KEV ∪ Metasploit ∪ ExploitDB: both qualify (both have Metasploit modules), and the doc's framing as "exploited but out-of-NP+DI-scope" is correct. But that's a broader definition than other parts of the doc imply.
- If something else (active campaign reports, Mythos signal, etc.): worth being explicit.

The CVE-2019-0232 (Tomcat CGI) row in the doc's table also confirms the broader definition — it's marked exploited (1 MSF module flag) but isn't in CISA KEV. So the doc IS using the broader definition. We just want to confirm and document it explicitly so future audits don't get confused.

---

## 4. Tomcat PUT (CVE-2017-12615/12617) — present in manifest scope, missing from misses table

### What we observe

The doc's misses table lists three NP+DI failures. There are KEV-confirmed Tomcat events in the manifest scope that aren't listed:

- **CVE-2017-12615** — Tomcat PUT to upload JSP (Windows) — CWE-434 — IN KEV ✓ — IN MSF ✓ — IN ExploitDB ✓
- **CVE-2017-12617** — Tomcat PUT variant (initial-fix bypass) — CWE-434 — IN KEV ✓ — IN MSF ✓ — IN ExploitDB ✓
- **CVE-2016-3088** — ActiveMQ FileServer file upload — CWE-20, 434 — IN KEV ✓ — IN MSF ✓ — IN ExploitDB ✓
- **CVE-2023-46604** — ActiveMQ Jolokia RCE (older) — CWE-502 — IN KEV ✓ — IN MSF ✓

By the same logic that lands CVE-2025-24813 (Tomcat partial PUT, CWE-502) in the misses table — "deserialization via HTTP PUT; grey-area DI boundary" — these earlier file-upload CWE-434 events should also be misses. They're DI by attacker mechanism (untrusted input drives a security decision: where to write a file) but classified as CWE-434 which isn't in the project's PARSING_CWES set.

### Question 4

**Why are these Tomcat-PUT-class events not in the misses table?**

Three plausible explanations:
1. **Out of analysis window**: maybe the doc's 7-year window is 2019+ rather than 2018+, and these older events were excluded? But CVE-2017-12617 is published 2018-10-17, in window.
2. **Considered "older known issues" assumed already patched**: the doc may have treated these as historical baseline that wouldn't trigger a 7-year-window analysis because mature shops wouldn't have an unpatched 2017 Tomcat. Reasonable, but should be documented.
3. **Curation choice**: the doc only listed the three most operationally-relevant misses (Ghostcat, partial PUT 2025, ActiveMQ 2026) as illustrative, not exhaustive. Reasonable, but the claim "5 of 8" implies an exhaustive count.

The interpretation matters because it changes the catch rate. If we include all Tomcat-PUT-class misses, the rate becomes 5/(5+5+) instead of 5/8.

---

## 5. The CWE-502 deserialization decision

### What we observe

The doc explicitly excludes CWE-502 from DI (per the "Deserialization Question" callout at periodicity.html lines ~414-422):

> "Deserialization is a CVE volume generator (historically), not an exploitation driver. In the KEV backtest, deserialization accounts for 3.8% of entries — and those are all product-level (Exchange, WebLogic, ColdFusion), not library-level. The real rebuild triggers were path traversal, template injection, and SQL injection."

But the misses table includes:

- CVE-2025-24813 (Tomcat partial PUT) — CWE-502 only
- CVE-2023-46604 (ActiveMQ Jolokia, older) — CWE-502 only [our finding, not in doc's table]
- SnakeYAML — CWE-502
- Log4Shell is double-tagged with CWE-502 alongside CWE-917

If we widen DI to include CWE-502, two things happen:
1. **Catch rate goes up** — the deserialization-class KEV events get caught
2. **False-positive rate explodes** — jackson-databind alone has 67 historical CWE-502 entries in this manifest, almost none of which became KEV

The user is unequivocal: adding CWE-502 to DI defeats the filter. Agreed.

### Question 5a

**The doc's prose strongly implies CWE-502 stays out of DI.** The misses table treats CWE-502 deserialization-via-HTTP-PUT as "grey-area DI boundary." Is the official position:
- (a) CWE-502 is never DI (filter-internal), and AI scan tier is responsible for catching the rare CWE-502 KEV events?
- (b) CWE-502 might be DI if the deserialization is reachable via HTTP request body / parameter, but that level of analysis is left to AI scan rather than CWE-tag matching?
- (c) Something else?

### Question 5b

**Same question for CWE-434 (file upload).** Tomcat PUT events use CWE-434 and are in KEV but not flagged by NP+DI. Same operational rationale — adding CWE-434 to NP would catch user-uploaded-file CVEs broadly, ballooning the trigger count. Is the official position:
- (a) CWE-434 is never NP+DI, AI scan handles
- (b) CWE-434 is NP+DI if combined with executable-content writes (JSP, etc.)?
- (c) Something else?

---

## 6. Hypothesis: NP+DI/high vs NP+DI/low

### What we found in the data

When you look at the 30 NP+DI events in the doc's canonical table:

- **5 reached exploitation evidence** (KEV or MSF): all are RCE primitives in widely-deployed packages
  - Tomcat CGI OS injection (1 MSF module)
  - XStream RCE (KEV via VMware NSX integration)
  - Log4Shell × 2 (KEV)
  - Spring4Shell (KEV)

- **5 are also RCE primitives but NOT exploited:**
  - spring-messaging SpEL RCE × 2 (CVE-2018-1275, -1270)
  - XStream Command injection (CVE-2013-7285)
  - XStream Code injection (CVE-2019-10173)
  - XStream OS command exec (CVE-2020-26217)

- **Same library produces both**: XStream has 1 caught (-39144) and 4 not-caught with similar bug classes. Spring Framework has Spring4Shell caught but spring-messaging SpEL RCE not caught.

This pattern suggests **"is it RCE?" doesn't discriminate within NP+DI**. The discriminator looks exogenous: did a famous public exploitation chain emerge? Did the CVE integrate with a popular product (NSX) that gave it deployment relevance? Did media drive scanning?

### Question 6

**Did you (the prior AI) analyze the within-NP+DI characteristics that predict exploitation?** The doc's framing ("the filter never told you to skip something that turned out to matter") implicitly treats all NP+DI events as equally high-priority. We tested whether that was a deliberate choice (acknowledging the discriminator is exogenous) or whether the within-NP+DI prioritization question was just out of scope at the time.

If you considered structural sub-priorities (CWE class, library breadth, pre-auth vs post-auth, etc.) and concluded none of them were reliable, we'd love to see the work. If you didn't, we'll do that analysis now and document the findings — including the null result if structural prediction doesn't pan out.

---

## What we'd want from you

For each numbered question above: a direct answer if you have one, "I don't remember / wasn't part of my analysis" if you don't, or "this was a deliberate methodology choice for X reason" if it was. We'll fold the answers into a methodology-correction commit on the periodicity page so future audits don't have to re-derive any of this.

The stored datasets in `data/` are what we used to build this reconciliation. They're reproducible from the cached inputs (see `tests/run.sh` and the `--check` mode of each generator script). If you spot a methodology issue with how we built any of those, please flag — we'd rather discover the error in the canonical data now than have it propagate into the methodology correction.

Thanks. Hoping we can get to a clean, audit-stable version of the periodicity claims that survives independent reproduction.

— Claude (current session)
