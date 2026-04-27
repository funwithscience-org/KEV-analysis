# Periodicity Analysis & Walkthrough Restructuring Review

**Date:** 2026-04-27
**Author:** kev-analyst (scheduled run)
**Scope:** review the new periodicity work (`docs/periodicity.html`), the CVE reference (`docs/cve-reference.html`), and recommend changes to the walkthrough (`docs/index.html`) and dashboard (`docs/dashboard.html`).

---

## 0. Headline (read this if you read nothing else)

The brief asks "the walkthrough was written before the periodicity analysis existed; recommend a restructure." That premise is **partly outdated** — the walkthrough has already been substantially restructured around threat-centric prioritization, the structure test (NP+DI), the attacker test (hacker S+A), the 7-year backtest, EPSS comparison, the kill-chain framing, and the Cat 1/2/3 estate-maturity model. Sections 3, 4, 7, 8 and 9 are now post-periodicity-analysis content. The brief's mental model ("the walkthrough is still the original observational analysis") is two rewrite passes behind reality.

That doesn't mean nothing needs to change. It means the work is **convergence and tightening**, not "graft a periodicity story onto an observational page." Concretely:

1. **Cut content the new model has obsoleted.** The §6 "Time-to-Exploit Compression" framing (251d → 11d → 30-day SLA is dead) now reads as orphaned old-thesis content next to §3–§4. The §10 reverse-proxy section is now redundant with §9a (WAF Dividend) on its own page. Section §5 ("why most criticals don't get exploited") still uses the survivorship-bias framing rather than the model framing.
2. **Move content that already lives on `periodicity.html` out of the walkthrough.** §4f (the 7-year manifest table, strategy efficiency, the 13 NP+DI library list) is high-value but it is now the third copy of substantially the same data (also on `periodicity.html` and partly on `dashboard.html`). Pick one canonical home and link from the others.
3. **Stop calling the OS layer "21 LPE CVEs."** The hacker-pass NVD-keyword-noise finding (cleaned LPE count is ~10–12, not 21) is in the periodicity page and acknowledged as a footnote on the walkthrough §7 table. The headline number on dashboard.html and on the §7 walkthrough KPI tile is still 21 with no caveat. Either change the headline or move the caveat next to the headline.
4. **The "zero-miss" finding is overstated and the page knows it but the framing is leaking.** The 12-month backtest has N=1 in-scope exploited CVE (Django `CVE-2025-64459`). "Zero of 113 non-triggers in KEV" is technically true but the discriminator can't be scored on N=1. The honest framing is on the periodicity page §The Cross-Framework Headline and on walkthrough §4b — but the dashboard banner ("0 misses in 12 months") and the §9 quick-checklist callout still inherit the overstated version.
5. **Periodicity page should stay separate.** Don't fold it back into the walkthrough — its purpose is to be the reproducible reference work that the walkthrough makes claims against. The architectural goal is "walkthrough = the argument; periodicity = the evidence; CVE reference = the audit trail; dashboard = the live data; build-mechanics = the operational how-to."

The rest of this report is the per-section accounting.

---

## 1. Assessment of the Periodicity Analysis

### 1.1 Is the NP+DI methodology sound?

**Mostly yes, with three honest weaknesses the page acknowledges.**

What's strong:

- The two-condition definition (NP = parses untrusted network input; DI = CWE in a defined set) is mechanical, falsifiable, and the CWE set is enumerated explicitly (walkthrough §3b table). A reviewer can disagree with a specific package's NP classification and re-run the filter — `cve-reference.html` is exactly the audit trail you'd want for that.
- The widened DI set (auth bypass via input manipulation: CWE-287, -289, -306, -345, -693, -863, -1321) is the right correction. The pre-widening v1 missed three Spring Security auth bypass criticals that would have been correctly caught — the rationale ("untrusted input that changes a security decision is the same pattern as injection") is defensible and consistent with the trust-boundary framing in the CLAUDE memory.
- CWE-444 (HTTP request smuggling) was added after external review; without it Netty's 12-month NP+DI count would have been zero. Including it surfaces a real exploitation class without expanding the set into noise.
- Cross-framework is the right test for whether the filter is ecosystem-portable, and the answer is yes (Spring/Node/Django all show 14 all-C/H dates → 2-6 NP+DI dates, with similar reduction profile).

What's weak:

- **CWE classification quality is the filter's blast radius.** The 7-year backtest finds 3 NP+DI raw misses (Ghostcat, Tomcat partial-PUT 2025-24813, ActiveMQ Jolokia 2026-34197) — all are NP libraries with the right DI primitive but the upstream CWE was wrong (CWE-269, CWE-502, CWE-20 respectively). The filter's answer was correct given its input; the input was bad. The DQ ("AI scan") layer is the proposed fix. **This is a real dependency on a third party (NVD/CNA CWE quality) that the walkthrough should be honest about up front, not buried in a §4f-table footnote.**
- **NP classification is a judgment call at the boundary** — the periodicity page says so explicitly. cryptography (Python) and BouncyCastle (Java) are the cleanest test cases for the trust-boundary rule (NP if it consumes untrusted tokens / certs / signatures from the wire) and the cve-reference page should make the boundary call visible per-CVE. Currently the rule is described in CLAUDE.md memory and the periodicity page §The Four Sample Stacks footnote, but a casual reader may not pick it up.
- **The 12-month synthetic-stack test cannot score discrimination.** N=1 actually-exploited CVE in window. "Zero misses across 113 non-triggers" reads better than it actually is — it's a statement about the population not the filter. The 7-year backtest is where scoring happens (10/13 hacker S+A direct, 11/13 union, 9/13 NP+DI+DQ). The page acknowledges this in two places but the executive-summary headline still reads "zero misses in 12 months" — keep removing that framing wherever it surfaces.

### 1.2 Is the cross-framework validation convincing?

**Yes, with caveats about what it does and doesn't prove.**

What it proves: the noise-floor reduction (14 → 2-6 events) is ecosystem-independent. Maven, npm, and PyPI all behave the same way under the filter, which means the NP+DI rule isn't a Java-specific or HTTP-server-specific artifact. Netty was a useful late add — its 3-events-per-year baseline shows the test isn't dependent on the 14-events-per-year synthetic stack assumption.

What it doesn't prove: that the surviving 2-6 events are the right 2-6. That requires ground truth. The 7-year backtest does this; the 12-month windows don't (N=1 isn't ground truth, it's a single observation).

The Django "honest weak case" framing is a strength — the analysis explicitly calls out that Django's recurring CWE-89 SQLi pattern leaves the filter at 71% reduction rather than 86%. A page that hid this would be less credible.

### 1.3 Is the OS chaining / kill chain framing correct?

**Directionally yes, but the numbers are inflated by NVD keyword noise and the page is not yet consistent about saying so.**

The structural finding ("the OS layer doesn't drive emergency rebuild cadence; the app layer does; OS refresh on a regular cadence controls blast radius") is sound. NP+DI = 0 on the OS container layer in 12 months is a clean negative result — there literally is no app-layer-style trigger pattern coming from libcurl, OpenSSL, libxml2, etc. in that window.

The 21 LPE / 76% reduction number is the problem. The hacker pass (called out in periodicity.html §The OS Layer and footnoted in walkthrough §7) found that ~50 of the 69 "OS layer" CVEs are NVD keyword false-positives — kernel CVEs matched via systemd, sqlite-using applications matched as sqlite, snapd which isn't in Amazon Linux 2023, etc. The cleaned LPE-relevant figure is ~10-12, not 21. Monthly refresh's actual reduction is probably 60-70%, not 76%.

Both pages now footnote this. **Neither updates the headline number.** Recommendation: either update the headline (preferred) or move the footnote next to the headline so a reader scanning KPI tiles can't walk away with the inflated figure. The dashboard's "OS Container Privesc Accumulation" chart is the most exposed surface — it shows 21 with no caveat.

### 1.4 Does the EPSS / external-validation analysis hold up?

**Yes — this is some of the strongest content on the page.**

The reframing of EPSS as complementary rather than competitive is the right take. EPSS is retrospective by construction — it scores the world's reaction to a CVE. NP+DI fires on disclosure-day structure. They answer different questions:

- "Should I drop everything right now?" → structure filter
- "Which of my unpatched backlog matters most?" → EPSS

The day-0 / day-7 / day-30 EPSS catch table on periodicity.html is the cleanest comparison I've seen. Log4Shell at 0.159 on day 1, XStream RCE at 0.018 for a month, ActiveMQ never crossing 0.50 — these aren't EPSS bugs, they're a feature: EPSS needs signal accumulation. The structure filter gets 9/13 (or 11/13 with hacker S+A) on day zero. EPSS catches up eventually.

The "zero misses" framing on the 12-month window is overstated (see §1.1) but **on the 7-year backtest the framing is honest**: 11/13 directly, 2/13 (Tomcat HTTP PUT 2017 pair) absorbed by supplementary controls — floor-sweep on adjacent Tomcat NP+DI rebuilds, not WAFs. This is the right narrative.

KEV cross-reference is correctly disclaimed: KEV is product-biased (Fortinet/Cisco/Exchange dominate) so a 0% library-CVE KEV rate doesn't validate the filter so much as expose KEV's coverage gap. ExploitDB / Nuclei / Metasploit hits are sparse but consistent (Django SQLi shows up in 3 sources; zlib in 2; nothing else surfaces). I would not lean on these as standalone validation, and the page doesn't.

### 1.5 Devil's-advocate: what could undermine the conclusions?

I am asked to play the other side, so:

1. **Survivorship bias in the 7-year manifest.** The 60-package enterprise Java manifest was selected by someone who knew which exploited CVEs they wanted to test. If the manifest had been chosen blind in 2018 and frozen, would it still contain the libraries that produced the 13 in-scope exploited events? Probably mostly — Tomcat, Spring, log4j, jackson, XStream, ActiveMQ are obvious enterprise picks — but a fully prospective test would be cleaner. The honest move is to freeze the current manifest and re-score quarterly going forward; that's the curmudgeon's "prospective test" demand from the previous review round.
2. **CWE set drift.** CWE-444 was added after Netty was tested and is a non-trivial addition — it lifts Netty from 0 to 1 trigger. If the next external review surfaces another defensible addition (CWE-502 with HTTP entry point? CWE-829 / -732 with network reachability?), the filter's reduction-from-noise claim weakens because the discriminator's specificity drops. The recommended fix (which the analysis hints at) is to freeze the CWE set, version it (NP+DI v1, v2 with auth-bypass widening, v3 with CWE-444), and report results against frozen versions.
3. **The 7-year manifest is Spring-centric.** XStream + Tomcat + Log4j + jackson + Spring4Shell + Thymeleaf is most of the in-scope exploited list. If we re-ran against a similar 7-year Node manifest or Python manifest, the exploited-CVE list would be much shorter (the synthetic 12-month windows already show this). The result would still be "filter caught what was caught" but the absolute numbers would differ enough to make the 11/13 headline unrepresentative. The fix is more 7-year manifests, not abandoning this one — but the page should be more careful when generalizing from 13 events.
4. **The Tomcat HTTP PUT pair as "absorbed by supplements" is partial circular reasoning.** The argument is: hacker B-tier'd them, supplements absorbed them, therefore the model is fine. But "supplements" includes "the team's normal update cadence" — which is exactly what we're choosing to delay vs. emergency. If the supplements are doing all the work for B-tier events, the 11/13 vs 13/13 distinction collapses into "you patch eventually anyway." The honest reframing is: the model claims emergency response should fire on S+A; B-tier events are still patched, just on cadence. That's defensible, but the "11/13 directly + 2/13 absorbed = 13/13" framing makes it sound like the model independently catches everything when it actually relies on the team having functioning Cat 1/Cat 2 cadence to absorb the B-tiers.
5. **Anchoring effect from Log4Shell / Spring4Shell / Ghostcat.** These are the most-studied CVEs in recent enterprise Java history. Any reasonable filter built by people who know these stories will catch them. The 7-year backtest is partly testing whether the filter we built remembers what we know it should remember. The forward-validation period (the daily watch-list run, the prospective test) is where this concern actually gets resolved.

None of these kill the analysis. They all argue for *less confident framing* and *more emphasis on prospective testing*.

---

## 2. Walkthrough Restructuring Recommendations

### 2.1 Honest assessment of where the walkthrough is now

The brief said the walkthrough was "the original observational analysis." That hasn't been true since at least the late-April rewrite. The current sections are:

| § | Heading | State |
|---|---|---|
| 1 | The Problem | Up-to-date with new framing (Cat 1/2/3 introduced informally). Keep. |
| 2 | The First Clue: Where Exploits Land | Observational content (KEV/NVD by layer, HTTP-parsing lift, OSV libraries). Keep but tighten. |
| 3 | Threat-Centric Prioritization (NP+DI + Hacker) | This is the new model. Keep. |
| 4 | Does It Actually Work? Cross-Framework Validation | This *is* the periodicity analysis on the walkthrough. Keep but consider trimming. |
| 5 | Why Most Criticals Don't Get Exploited | Pre-model framing. Either re-anchor against the model or move to caveats. |
| 6 | Time-to-Exploit Compression | Pre-model. Now feels orphaned. See §2.4 below. |
| 7 | Land & Expand: Kill Chain (OS layer) | New content. Keep but fix headline number per §1.3. |
| 8 | External Validation (EPSS / KEV / etc.) | New content. Keep. |
| 9 | Operational Response by Estate Maturity | New content. Keep. Most important section for the "what do I do" reader. |
| 10 | The Reverse Proxy Myth | Defense-in-depth. Now overlaps with §9a. Trim to a callout. |
| 11 | Exploit Watch List | Live operational content. Keep. |
| 12 | Caveats | Already updated with periodicity caveats. Keep. |

**The walkthrough has already absorbed the periodicity findings.** The remaining issues are convergence (sections that reference different versions of the same number), framing (orphaned pre-model sections), and architecture (content duplication between walkthrough / periodicity / dashboard).

### 2.2 Section-by-section recommendations

**§1 — The Problem.** Keep. The Cat 1/2/3 informal introduction is good; section 9 formalizes it. Consider front-loading the §9 callout link earlier.

**§2 — Where Exploits Land.** Keep but tighten. §2a (stack layer rates) and §2b (network-parsing CVSS lift) are the foundational empirical results. §2c (libraries / OSV / 770-vs-93000 denominator) is the strongest argument for why CVSS-based prioritization fails in the first place. Trimming candidate: the 100% email_collab_server rate is an upper-bound artifact and the table can lose it from the prose if not from the data, since it confuses readers into thinking the methodology is broken rather than that the denominator is small.

**§3 — Threat-Centric Prioritization (NP+DI + Hacker).** Keep. This is the centerpiece. Two suggestions:
- §3b (the DI CWE table) is dense. Split into "structural injection" (78, 77, 22, 23, 36, 89, 94, 95, 918, 917, 1336, 116, 74, 75, 113, 93, 611, 91, 90, 79, 444) and "auth-bypass-widening" (287, 289, 306, 345, 693, 863, 1321 — currently not shown explicitly in the table). The widened set is referenced in prose ("widened DI definition") but a reader scanning the table sees only the first set. Add the second-tier table beneath or as a continuation.
- §3d (hacker discriminator) is good but could use a worked example. Spring4Shell as S/A walkthrough, Tomcat HTTP PUT as B walkthrough, Multer DoS as D walkthrough. The hacker tier rules are described abstractly; a reader benefits from seeing the rubric run on three concrete events.

**§4 — Does It Actually Work? Cross-Framework Validation.** Keep but consider trimming.
- §4a–§4e (synthetic 12-month) — keep. Explicitly call out N=1 in §4b instead of §4d (currently the honest caveat is in §4b but the "0 misses" hero stat is in §4a).
- §4f (real-world enterprise Java case study) — this is a long subsection (table + funnel + 13-library breakdown + DQ-pass discussion + structure-vs-attacker comparison). It's high-value but it is the third place this content lives (also `periodicity.html` and `cve-reference.html`). Recommendation: shrink the on-page table to just the strategy comparison row and "11/13 union," then deep-link into periodicity.html for the per-CVE list and DQ-pass details. The 13-library NP+DI table can move to periodicity.html or the CVE reference. The walkthrough should *make the claim*; the periodicity page should *defend the claim*.

**§5 — Why Most Criticals Don't Get Exploited.** Re-frame. Currently this reads as a pre-model survivorship-bias narrative. The new model framing would be: §3 told you which CVEs *will* be exploited; §5 explains why everything else *won't*. The factual content (firmware/kernel-local/IoT/memory-corruption/library-variance/non-Western) is still right; the framing should be "these are the populations the filter correctly excludes." The §5 "browser UAF is the exception" callout is important and should be retained — it's the only place we acknowledge that client-side dynamics differ from server-side, which matters for the watch list's desktop entries.

**§6 — Time-to-Exploit Compression.** Demote or remove. The 251d → 11d → 30-day-SLA-is-dead framing was the earlier thesis's payoff. The current model says the SLA framing is the wrong question — it's not "patch in 30 days" or "patch in 7 days" or "patch in 72 hours," it's "emergency response for NP+DI + hacker S+A; cadence for everything else." The 11-day TTE data point is still factual but it's now in service of the §3 / §9 model, not a standalone conclusion. Recommendation: fold the TTE chart into §3e (the "hidden cost of not filtering" argument) — the 11-day TTE is *why* you can't run "patch all C/H" at all-C/H volume. It justifies the model rather than competing with it.

**§7 — Land & Expand (OS layer).** Keep. Fix the headline number. Either update the §7 KPI tile from 21 to 10-12 or place a "*see noise note*" caveat directly on the tile. The current state — tile says 21, prose says 21, footnote on the per-date table says "actual is 10-12" — leaves the casual reader with the inflated figure. Ditto the "76% reduction" prose. The structural finding (monthly cadence is the efficient frontier) is unchanged.

**§8 — External Validation.** Keep. The 7-year backtest table (NP+DI raw 6/13, NP+DI+DQ 9/13, hacker S+A 10/13, union 11/13) is the right honest scorecard. Keep flagging that the union plus supplements "handles 13 of 13" but be careful that the "supplements absorb 2/13" framing isn't doing too much work — see §1.5 devil's-advocate point #4.

**§9 — Operational Response by Estate Maturity.** Keep. This is the most important section for an operational reader. The Cat 1/2/3 framing is honest about the fact that the same model produces different responses depending on team maturity. The cross-link to `build-mechanics.html` is the right architecture — the walkthrough makes the argument; build-mechanics has the operational how-to. §9a (WAF Dividend) is good; consider promoting the "DI bug classes are structurally visible to WAFs while CWE-502 isn't" point — it's a non-obvious justification for why the DI set is what it is.

**§10 — Reverse Proxy Myth.** Trim to a callout. Most of this content is now better expressed as "WAFs are the bridge, reverse proxies are the pipe" inside §9a. The expandable details (path constraint, request size limits, header stripping) can live in `build-mechanics.html` if not already there.

**§11 — Exploit Watch List.** Keep. The hacker-tier column is the right addition. Continue daily updates. Note the ongoing hit-rate (5 of 14 watch entries promoted to KEV — Marimo, SharePoint, ActiveMQ, Adobe Acrobat, Defender BlueHammer) is the prospective test the curmudgeon demanded; consider surfacing the running hit-rate as a KPI tile.

**§12 — Caveats.** Already periodicity-aware. Keep. Add: "filter logic is only as good as the upstream CWE tagging; the DQ layer addresses this but the dependency exists" — this is the most important caveat and currently it's spread across §4f and the 7-year-table footnotes rather than called out in §12.

### 2.3 Where the periodicity / patching findings live in the narrative

They already live in §3 / §4 / §7 / §8 / §9. The story arc is:

1. §1: there's too much patching noise.
2. §2: not all CVEs are equal — network parsers are 3-6× exploited.
3. §3: the model — NP+DI + hacker S+A.
4. §4: the model works across ecosystems.
5. §5: here's why everything else doesn't get exploited (re-framed against the model).
6. §6: time-to-exploit is short, which is why you can't run "patch all" at scale (re-framed as supporting §3e rather than standalone).
7. §7: the OS layer is different — it sets blast radius, not cadence.
8. §8: external validation.
9. §9: what to do with this (Cat 1/2/3 + WAF dividend).
10. §10: reverse proxy is just a pipe (trimmed callout).
11. §11: live scorecard.
12. §12: caveats.

This is a coherent arc. The work is tightening, not restructuring.

### 2.4 The "zero-miss" finding

Three places it currently appears:

- **Walkthrough §4a hero KPI:** "0 skipped events later confirmed exploited" — overstated for the 12-month window.
- **Dashboard banner:** "0 misses in 12 months" — overstated.
- **Walkthrough §8 "honest scorecard":** "11 of 13 directly + 2/13 absorbed by supplements" — accurate.

Recommendation: replace the §4a hero stat from "0 skipped events" to either (a) "11/13 union catch + 2 absorbed" with a 7-year framing, or (b) "N=1 in 12mo — see §4b for honest framing." Also update the dashboard banner.

### 2.5 The three-tier patching model presentation

Currently §9 (estate maturity) and §9a (WAF dividend) cover this. The walkthrough's framing — emergency for NP+DI / hacker S+A, cadence for OS container, cycle for everything else — is correct.

Two recommendations:

1. **Don't call it "three-tier" anymore.** Memory note CLAUDE.md says: "Estate maturity = Cat 1/2/3 ... replaces the older 'Tier 1/2/3 patching model' entirely." The dashboard still shows "Three-Tier Patching Model" in a card with Tier 1/2/3 labels (lines 331-339). That's the old framing — Cat 1/2/3 is about *who can absorb a patch*, not *what kind of trigger fires*. The dashboard card is now inconsistent with the walkthrough §9.
2. **Be explicit that the trigger axis (emergency / cadence / cycle) and the maturity axis (Cat 1 / Cat 2 / Cat 3) are independent.** A Cat 1 team handles all three triggers in BAU; a Cat 3 team needs hand-rolled emergency response for the first trigger. The current walkthrough §9 callout-finding does say this but it could be a 2×3 grid for clarity.

---

## 3. Dashboard Updates

### 3.1 What to add / change

1. **Update the Tier 1/2/3 card** (dashboard.html lines ~321-340) to use Cat 1 / Cat 2 / Cat 3 framing instead. The current card describes the trigger axis (NP+DI / monthly / cycle) under the "Tier" heading — that's the legacy framing. Either:
   - relabel the card as "Trigger axis" with Tier 1/2/3 (current content) and add a second card "Estate maturity (Cat 1/2/3)" — pulling from walkthrough §9, or
   - replace the card entirely with the 2×3 grid.
2. **Update the "0 misses in 12 months" banner.** Either remove or qualify.
3. **The OS Container Privesc Accumulation chart** shows 21 LPE without the keyword-noise caveat. Either annotate the chart or use the cleaned 10-12 figure.
4. **Add a watch-list KPI tile.** "5 of 14 promoted to KEV — Marimo, SharePoint, ActiveMQ, Adobe Acrobat, BlueHammer" or similar. The watch list's hit rate is the prospective validation; surfacing it makes the analysis defensible.
5. **Consider removing the "Three-Tier Patching Model" card title** in favor of clearer cross-references to walkthrough §9 and build-mechanics.

### 3.2 What's now stale

- The dashboard's "Three-Tier Patching Model" card title (legacy framing).
- The dashboard's "0 misses in 12 months" banner.
- The OS chart's 21-without-caveat headline number.

### 3.3 What to leave alone

The dashboard's primary value is fast-loading data charts. It should not become a second walkthrough. Most of the existing charts (layer rates, HTTP-parsing lift, TTE, CWE families, ransomware, top products, searchable KEV table) are fine. The cross-framework chart and the OS privesc chart are the right *additions* — don't add more periodicity charts; let `periodicity.html` be the deep dive.

---

## 4. Cross-Page Architecture

### 4.1 Page roles (recommended)

| Page | Role | Audience |
|---|---|---|
| `index.html` (walkthrough) | The argument. End-to-end story from problem → model → validation → operational response. | New reader, sets the case. |
| `periodicity.html` | The evidence. Reproducible cross-framework + 7-year backtest with the supporting tables and per-event reasoning. | Skeptical reader who wants to verify or adopt. |
| `cve-reference.html` | The audit trail. Per-CVE classification of every event in scope. | Reviewer, adopting team. |
| `dashboard.html` | The live scorecard. Daily-refreshed data with charts and the searchable KEV catalog. | Operational reader, recurring visit. |
| `build-mechanics.html` | The how-to. Cat 1/2/3 estate maturity, WAF as bridge, get-newest builds, application metadata. | Implementer. |
| `glasswing.html` | The intelligence assessment. Mythos-related speculation kept separate from data. | Reader interested in the AI-vulnerability-research angle. |

This structure already exists. The work is making sure each page stays in its lane — content currently duplicated between walkthrough and periodicity (the 7-year strategy table, the 13-library NP+DI table) should be linked rather than duplicated.

### 4.2 Front-door experience

The walkthrough is the front door, and the "How to read this site" table at the top (5 minutes, 30 minutes, want to verify, want it live, want build mechanics, want the AI angle) is the right onboarding pattern. Keep. Consider adding an explicit "what's new since last quarter" callout for repeat visitors — currently the site presents as a single document rather than a living analysis.

### 4.3 Navigation

Top-nav (Walkthrough / Dashboard / Periodicity / Build Mechanics / CVE Reference / Mythos) is consistent across pages. Keep.

The walkthrough's left sidebar nav is good but lengthy at 12 sections. After the trims recommended in §2.2 (§6 demoted to §3e supporting, §10 trimmed to a §9 callout), the sidebar would have 10 sections, which is closer to scan-friendly.

---

## 5. Summary of Recommended Actions (ordered by impact)

1. **Update the "21 LPE / 76% reduction" headline** on dashboard + walkthrough §7 to either the cleaned figure (10-12) or place the noise caveat next to the headline. Highest priority — readers walk away with the inflated number today.
2. **Update / remove the "0 misses in 12 months" framing** on dashboard banner + walkthrough §4a hero KPI. It's overstated; the honest framing is on the periodicity page and walkthrough §8 already.
3. **Update the dashboard "Three-Tier Patching Model" card** to use Cat 1/2/3 estate-maturity framing or split into "Trigger axis" + "Estate maturity" cards. Currently inconsistent with the walkthrough.
4. **Trim walkthrough §4f.** Move the per-CVE detail and 13-library table to periodicity.html; keep just the strategy comparison row + "11/13 union" claim on the walkthrough with a deep link.
5. **Re-frame walkthrough §5 and §6** as supporting the model rather than standing alone. §6 (TTE) is best folded into §3e ("the hidden cost of not filtering"); §5 (survivorship) re-anchored as "what the filter correctly excludes."
6. **Trim walkthrough §10** to a callout under §9 / §9a.
7. **Add a watch-list hit-rate KPI tile to the dashboard** (5/14 promoted to KEV). This is the cleanest prospective-validation surface.
8. **Add the auth-bypass-widening CWEs (287, 289, 306, 345, 693, 863, 1321) to the §3b DI table** explicitly. They're referenced in prose but not in the table.
9. **Add a worked example to §3d** (hacker discriminator). Spring4Shell as S/A, Tomcat HTTP PUT as B, Multer DoS as D. The rubric is described abstractly — concrete examples land it.
10. **Consider freezing the CWE set with an explicit version** (NP+DI v3 = original + auth-bypass-widening + CWE-444). Curmudgeon demand from prior review round; relevant for prospective-test integrity.

The walkthrough should NOT be restructured. It should be tightened, dedup'd against periodicity.html, and have its overstated headlines pulled back to match the honest framing already present in the body.

---

## 6. Daily Scan (2026-04-27)

### KEV
- catalogVersion 2026.04.24, total 1583, April KEV total = 28. **No KEV update in the last 24 hours** (last release 2026-04-24, 4-entry batch: D-Link, Samsung, SimpleHelp pair). This is a 3-day KEV silence — within normal range, but BlueHammer / Marimo / n8n watch entries that hit PoC weeks ago still aren't all in (n8n still WATCHING; the 5 confirmed are noted in the watch list).
- Most recent April activity (per kev-tracking.json): Cisco SD-WAN cluster 2026-04-20 (8-entry batch, all HTTP-parsing-adjacent — see rolling 2026-04-21 for the 46-day exploitation-to-KEV gap that reframes the falsification window).
- Watch-list hit rate stays at **5 of 14 promoted to KEV** (Marimo, SharePoint, ActiveMQ, Adobe Acrobat, Defender BlueHammer). 9 still WATCHING. Two wolfSSL events (CVE-2026-5194, -5501) and the Thymeleaf SSTI pair (CVE-2026-40477, -40478) are the most-watched candidates.

### NVD volume
- April MTD = 5174 (day 27 of 30). Day-over-day +91 CVEs (slow Sunday tail). Extrapolation 5748, ~9% below March (6304), within Q1 churn band (4808-6304).
- Three weeks of volume softening continues to argue *against* the "AI is flooding CVE" framing. Mythos-driven volume shock would have to wait 4-8 weeks for NVD assignment latency, but the running rate is below baseline, not above it. Counter-argument continues: latency could mask a Mythos surge that hasn't reached NVD yet — the data cannot distinguish "no surge" from "surge in the publishing pipeline" until mid-May.

### Glasswing / Mythos
- Glasswing CVE count holds at **283** (271 Firefox 150 / MFSA 2026-30, 9 wolfSSL, 1 each F5 NGINX Plus / FreeBSD / OpenSSL). No new participant products surfaced.
- Claude-credited known: 6 (CVE-2026-4747 FreeBSD NFS autonomous, CVE-2026-5194 wolfSSL cert validation Mythos-Preview-assisted, CVE-2026-5588 Bouncy Castle Carlini+Claude, plus three Firefox 150 entries CVE-2026-6746/6757/6758). No new credits in 24h.
- Candidate flagged for review: CVE-2026-2796 (Firefox) — referenced in Anthropic red-team blog as a Claude-written exploit demo. Appears to be a March-2026 Firefox bug from the pre-Glasswing Mozilla collaboration. Not adding to claude_credited_cves without explicit MFSA credit.

### Glasswing-participant cross-check (today)
- April KEV adds since prior reports include Cisco SD-WAN cluster (Cisco = participant), Apple iOS / Multiple Products entries (Apple = participant), SharePoint and Office (Microsoft = participant). All consistent with the participant self-scan pattern (HTTP-parsing-adjacent, no third-party credit, automated-scan-shaped). No new entries qualify for the probable-participant-self-scan table beyond the existing four Cisco entries (CVE-2026-20180, -20186, -20147 ISE RCE, -20184 Webex SSO).
- No new attribution-shaped CVEs in the 24h window.

### Notable / non-routine
- The watch-list now has stable enough cadence (5 promotions in 6 weeks) to surface the running hit-rate as a dashboard KPI — see recommendation #7 in §5.
- The "Mythos-driven volume shock" question continues to lack discriminating evidence. The honest framing (rolling.md 2026-04-19 onward) is that the data cannot distinguish "no Mythos exploitation" from "exploitation hasn't reached NVD/KEV yet" for another 8-12 weeks. No change to that framing today.

---

*End of review report. Recommendations are advisory; no HTML edits made by this run per the task brief instructions.*
