# Retrospective 30-Day Sweep: 2026-03-27 to 2026-04-26

One-time application of the (newly widened) threat-centric prioritization model to KEV / NVD-CRIT+HIGH / OSV inbound across the last 30 days, plus an April-2022 KEV baseline run for trigger-volume comparison.

Artifacts:
- `data/retro-model-run-2026-03-27-to-04-26.json` — per-event model output (311 rows)
- `data/retro-baseline-april-2022.json` — April-2022 KEV-only model output (45 rows)
- `data/_retro-nvd-2026-03-27-to-04-26.json` — raw NVD critical+high cache (1,368 entries)
- `data/_retro-osv-2026-03-27-to-04-26.json` — in-window OSV advisories (72 entries)

## 1. Headline

| Metric | Count |
|---|---|
| Events evaluated (KEV ∪ NVD-in-scope ∪ OSV-in-window) | **311** |
| KEV inbound (30-day window) | 30 |
| NVD critical+high in window (raw) | 1,368 |
| NVD in-scope after layer filter | 214 |
| OSV in-window for 52 NP packages | 72 |
| **Triggered (S/A or NP+DI or NP+DQ-pass)** | **67** (21.5%) |
| Autobuild lane (open-source, non-triggered) | 56 |
| BAU lane (KEV/commercial/OS, non-triggered) | 66 |
| Out of scope | 122 |
| **Newly caught by widening (NP+DI new ∧ ¬old)** | **14** |
| Watch-list backfill candidates (S/A, not currently tracked) | **35** raw → **~12** after de-duping downstream-app false positives (see §5) |

KEV-only triggered rate: **21/30 = 70%** (vs. 16/45 = 35.6% for April 2022 — see §4).

## 2. What the widening caught that the old filter missed

14 events have `would_new_filter_catch=true ∧ would_old_filter_catch=false`. After triage, the genuine wins are:

| CVE | Package | Why old missed | Why new catches | Recommendation |
|---|---|---|---|---|
| **CVE-2026-29145**, **CVE-2026-34500** | tomcat-embed-core (CLIENT_CERT bypass) | CWE-287 not in old DI set | Widened DI now includes CWE-287 (auth bypass via input) | Already in 12-mo backtest; **no action** (already documented) |
| **CVE-2026-34531** | Flask-HTTPAuth | Auth helper library wasn't NP under old rule | Widened NP includes auth/JWT/cert libs | **Add to watch list, A-tier, anchor: Spring-Security-AuthBypass** — ecosystem-wide reach via Flask apps that delegate to the lib, classic widened-NP+widened-DI case |
| **CVE-2026-33937**, **-33938**, **-33940** | handlebars (SSTI cluster, AST type confusion) | Template engines weren't NP | Widened NP includes template engines; CWE-94 always in DI | **Add cluster to watch list, A-tier, anchor: Handlebars-SSTI** — three already exist in `data/hacker-tiers.json` from R6 but not yet in config watch list |
| **CVE-2026-33916**, **-33941**, **GHSA-7rx3-28cr-v5wh** | handlebars (XSS / prototype-pollution / CLI) | Template engines weren't NP | Widened NP catches; CWE-79/-1321 in old DI but no NP match | Cluster context — already grouped above; **C-tier individual recommendations are watch-only** |

False positives among newly-caught (NP keyword matched a downstream app that uses but is not the NP package — flagged in caveats):
- CVE-2026-33031, -33432 (Nginx UI, Roxy-WI — apps that *manage* nginx, not nginx itself)
- CVE-2026-6577 (DjangoBlog — app, not Django framework)
- CVE-2026-40901 (DataEase — app that bundles Velocity .jar; the deserialization is real, but the catch is on the bundling, not on Velocity-the-package)
- CVE-2026-39363 (Vite dev server — `ejs` substring matched on "ejs template" elsewhere in the description; legitimate CVE but not really a template-engine catch)

The signal: **the widening genuinely earns its keep on the Tomcat CLIENT_CERT cluster, Flask-HTTPAuth, and the Handlebars SSTI cluster.** Everything else is either prior-known or downstream-app noise.

## 3. Trigger volume by week

| Week | Triggered | Autobuild | BAU | OOS | Total |
|---|---|---|---|---|---|
| Mar 27 – Apr 02 | 18 | 1 | 19 | 38 | 76 |
| Apr 03 – Apr 09 | 9 | 2 | 22 | 47 | 80 |
| Apr 10 – Apr 16 | 7 | 0 | 17 | 11 | 35 |
| Apr 17 – Apr 23 | 15 | 0 | 6 | 25 | 46 |
| Apr 24 – Apr 26 | 18 | 53 | 2 | 1 | 74 |
| **Total** | **67** | **56** | **66** | **122** | **311** |

Note: the spike in the final 3-day bucket is dominated by an OSV "modified" sweep (a single recent re-classification batch touched 50+ Rack/Tomcat/Django/Handlebars advisories and bumped them into our window via `modified` rather than `published`). That artificially inflates the autobuild lane in the last bucket. Triggered events in that bucket (18) are mostly the Handlebars SSTI cluster + a few re-touched ASP.NET Core / Authlib / Cryptography advisories.

**Workload interpretation:** triggered = 67 events / 30 days ≈ 2.2/day across the entire scope (KEV + NVD critical+high in HTTP-parsing-adjacent layers + 52 NP packages). Of those, only the **22 KEV-confirmed or NP-package-with-injection** events are realistically "drop everything." The other ~45 are in long-tail downstream apps (mlflow, OpenClaw, DataEase, Tautulli, etc.) where most consumers don't run them. **Real cadence-relevant triggered volume is ~3-5/week across the in-scope universe**, not the raw 67.

## 4. April 2026 vs April 2022 — does the routing model cut workload?

KEV-only comparison (apples-to-apples, since OSV/NVD coverage in 2022 is sparse):

| | Apr 2026 (last 30d) | Apr 2022 (calendar month) |
|---|---|---|
| Total KEV inbound | 30 | 45 |
| Triggered (S/A or NP+DI) | 21 (70%) | 16 (35.6%) |
| BAU lane | 9 (30%) | 29 (64.4%) |
| Tier S | 1 (Marimo) | 0 |
| Tier A | 20 | 16 |
| Tier B | 9 | 28 |
| Tier C | 0 | 1 |

**The triggered share went UP from 36% to 70%, not down.** This is the inverse of what the model was designed to do — but the right reading is that **the KEV input itself has shifted**, not that the model failed:

1. **Apr 2022 KEV was a backfill dump.** That month had 45 entries because CISA was retroactively ingesting ICS / firmware / pre-2015 Flash vulnerabilities (Adobe Flash Player ×6, IE memory corruption, Win32k LPE ×4, Linux Kernel Dirty Pipe). Those legacy-OS / kernel-LPE / document-RCE entries quite correctly fall in the BAU lane — the model never claimed to fire on them.
2. **Apr 2026 KEV is a weekly drumbeat of edge-appliance auth-bypass / RCE.** Cisco SD-WAN ×3, Fortinet FortiClient EMS ×2, Microsoft SharePoint, JetBrains TeamCity, Quest KACE, F5 BIG-IP, PaperCut, Synacor Zimbra, Citrix NetScaler, Marimo, ActiveMQ. These are *exactly* the network-edge primitives the hacker rubric tags A-tier.
3. The model fires correctly in both periods. The shift is in attacker selection / KEV editorial focus, not in the filter's behavior.

**Honest answer to the user's question:** the model does not "cut workload" relative to a 2022 baseline because the 2026 inbound is genuinely higher-density actionable. What the model *does* do is correctly route 30% (Apr 2026) to BAU vs the would-be naive read where every KEV entry is "patch now." It also kept 56 OSV library advisories in the autobuild lane that under a flat-priority CVSS-driven approach would have been treated as critical work items. **Workload reduction comes from routing, not from filtering.** A Cat-1 Spring shop in Apr 2026 has ~7 genuinely-on-them KEV entries (Marimo if they run it, ActiveMQ if they run it, Spring nothing this month, Tomcat CLIENT_CERT if they run mTLS) — far less than the raw 30.

## 5. Watch list backfill recommendations

Of 35 S/A-tier triggered events not currently on the watch list, the genuinely useful additions are:

| Proposed CVE | Tier | Anchor | Rationale (one line) |
|---|---|---|---|
| **CVE-2026-29145 / CVE-2026-34500** | A | Tomcat-CLIENT_CERT | Tomcat mTLS CLIENT_CERT auth bypass — cluster of 2; minority surface but live exploit pattern |
| **CVE-2026-34531** | A | Spring-Security-AuthBypass | Flask-HTTPAuth empty-token verification bypass — clean widened-NP catch |
| **CVE-2026-33937 / -33938 / -33940** | A | Handlebars-SSTI | Handlebars AST type confusion → JS injection (3 CVEs, R6-graded) |
| **CVE-2026-3902** | A | Django-ASGI-Header-Spoof | Django ASGI header spoofing (already in R4, surface for tracking) |
| **CVE-2025-57833 / -59681 / -64459** | A | Django-AnnotateValuesSQLi | Django column-aliases SQLi cluster (3 CVEs, all R4-graded; not in config watch list) |
| **CVE-2026-39324** | A | novel | Rack::Session cookie auth bypass + deser (CVSS 9.8, multi-CWE 287/345/502) — strong primitive |
| **CVE-2026-41242** | A | novel | protobufjs code injection in type fields (CVSS 9.8, CWE-94) — broad ecosystem reach |
| **CVE-2026-4800** | A | Lodash-Template-RCE | Lodash _.template incomplete fix (regression of CVE-2021-23337) |
| **CVE-2026-39892** | A | novel | cryptography (PyPI) buffer overflow on non-contiguous buffers — auth/cert-lib widening case, broad PyPI install base |

I am **not** recommending the Endian Firewall ×7 cluster, the SiYuan ×2, the various OpenClaw cluster, Nginx UI, Tautulli, mlflow, etc. — those are downstream-app catches that don't justify watch-list real estate; route them through the autobuild/BAU lanes instead.

## 6. Caveats

1. **"Newly caught by widening" includes 5 false positives** (Nginx UI, Roxy-WI, DjangoBlog, DataEase, Vite). The NP-keyword matcher hits substrings in advisory text where the package name appears as context ("Nginx UI manages nginx", "DjangoBlog uses Django"). For a one-time sweep this is acceptable — the genuine 9 catches are correctly identified — but a production filter would need package-name normalization (use OSV/CPE references not free-text).
2. **NVD coverage is good.** 341 CRITICAL + 1,027 HIGH was returned in single pages; no pagination cutoff. Cached at `data/_retro-nvd-2026-03-27-to-04-26.json`.
3. **OSV coverage is partial by design.** I queried 52 packages from the project's NP universe. Many in-window OSV advisories are `modified` not `published` (re-classifications adding CWE IDs), which inflates the volume but is honest about what's been touched. The filter window includes both.
4. **KEV entries lack CWE in the snapshot** — the per-CVE CWE field comes only from NVD enrichment. For KEV-only events older than the 30-day NVD window I used vendor/product/description heuristics to assign tier and anchor; almost everything lands as A-tier "novel" because edge-appliance KEV entries are virtually always direct primitives. Where stronger anchoring matters (ActiveMQ, Marimo) the canonical anchor is used.
5. **April 2022 baseline used text-based DI inference**, not CWE-based. The 16/45 triggered figure is conservative. If anything, the true April 2022 triggered share is slightly higher (a few of the BAU-tagged entries — VMware vRA cmd-inj, WatchGuard auth bypass — likely deserve A-tier on closer inspection). The headline conclusion (trigger ratio rose, not fell) is robust to this slack.
6. **Tier-anchor discipline:** of 311 events, 57 ended up at hacker-tier A, of which roughly half cite a canonical anchor (Spring4Shell, Handlebars-SSTI, Django-AnnotateValuesSQLi, ActiveMQ-Jolokia, MarimoMissingAuth, Tomcat-CLIENT_CERT, Tomcat-PartialPUT-Deser) and roughly half are marked `novel`. Most "novel" assignments are KEV edge-appliance entries (Cisco SD-WAN, Fortinet FortiClient, F5 BIG-IP, JetBrains TeamCity, Kentico) where the anchor list doesn't yet have a vendor-appliance class. **Recommend extending `data/hacker-tiers.json` with a "edge-appliance auth-bypass + RCE" anchor** (e.g. CVE-2026-1340 Ivanti EPMM as the canonical) so future runs don't keep stamping `novel`.
7. **Tests pass** (`tests/run.sh`): 178/178 data-invariants, 53/53 http-data, 4773/4773 classifications, 7yr/12mo backtest reproducible. No HTML/data files were modified by this sweep — only new artifacts under `data/` and one new report in `analyst-reports/`.
