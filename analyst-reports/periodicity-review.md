# Periodicity Analysis & Walkthrough Restructuring Review

**Date:** 2026-04-28
**Author:** kev-analyst (scheduled run)
**HEAD at review:** `171c9a5` (Operational Model §5 reflow)
**Scope:** review of `docs/periodicity.html`, `docs/cve-reference.html`, `docs/index.html`, `docs/dashboard.html` against the periodicity-review-brief task. This is the eighth analyst-side review pass; passes 4–7 live as `periodicity-review-pass{5,6,7}.md` and yesterday's standing report (`periodicity-review.md` at commit `b6059ca`). Today's pass overwrites that file with the current-state view.

---

## 0. Headline (read this if you read nothing else)

**The brief is two rewrite cycles out of date and the project knows it.** Yesterday's review explicitly called this out; today the gap is wider. Nearly every "should we add this?" item the brief raises is already in production, plus a new layer of work the brief never anticipated. Concretely, since the brief was written:

- The walkthrough has been rebuilt around the **threat-based prioritization model** with two complementary operationalizations (NP+DI structure test + hacker S+A attacker test), the DQ rescue layer, the 7-year backtest, the EPSS day-0/day-7/day-30 comparison, the kill-chain framing, the WAF-defensibility axis, and the Cat 1/2/3 estate-maturity model. Sections 3, 4, 7, 8, 9 are post-periodicity content. The brief's framing ("walkthrough is still the original observational analysis") is wrong against today's HEAD.
- A separate **Operational Model** page (`build-mechanics.html`, displayed as "Operational Model") covers Cat 1/2/3, BAU vs floor sweeps, the cat-2/cat-3 boundary, and WAFs-as-bridge — the operational how-to that the walkthrough §9 deep-links into.
- **The cve-reference page was rebuilt as a per-CVE audit trail with a WAF-defensibility column** (commits `c388de4`, `24c876e`).
- The "AI scan" tier was renamed to **DQ (Data Quality)** across the repo per CLAUDE memory; "threat-centric" was renamed to "**threat-based prioritization model**" (commit `60e657c`); "Build Mechanics" was renamed to "**Operational Model**" in display text (commit `d783226`).
- New EPSS framing on `periodicity.html` §15: **the model fires on disclosure day; EPSS catches the same set on average 34.7 days later at ≥ 0.10 and 131 days later at ≥ 0.50** (commits `a6a210c`, `1eb5328`, `88aca46`). This is the strongest piece of new analysis in the last 48 hours and the brief doesn't cover it because it didn't exist yet.

What this means for today's review: the work to do is **not** "graft a periodicity story onto an observational page." It's **convergence and pruning** — find the places where the old framing still leaks, clean up duplicated content, and update the few headline numbers that still inherit the overstated version. Major restructuring would be a regression.

The four still-actionable items, ordered by impact:

1. **The dashboard's "zero misses" framing is still live.** Line 166 still reads *"reduces rebuild-trigger dates by 64–86% with zero misses — no filtered-out CVE has appeared in CISA KEV."* Yesterday's review flagged this. Pass-5 flagged it as "highest urgency, ~5 min, must-ship-today." It's now five days unaddressed. The walkthrough §4b honest framing ("N=1 doesn't differentiate strategies from random") and the explicit 7-year backtest result (11/13, not 13/13) need to land in the dashboard banner too.
2. **`periodicity.html` still presents the "21 LPE / 76% reduction" headline without the noise-cleaned figure.** The walkthrough §7 absorbed the correction (60–70% on the cleaned set). The periodicity page §The OS Layer keeps both numbers in tension — the cadence-comparison table still shows 76% in green; the call-out next to it now says ~10–12 cleaned. The dashboard's "OS Container Privesc Accumulation" chart inherits the 21 figure with no caveat. Same fix for both: lead with the cleaned number, demote the raw 21 to a footnote.
3. **§4f content is still substantially duplicated across walkthrough, periodicity, and dashboard.** The strategy efficiency table (Patch all / NP+DI raw / NP+DI+DQ / Hacker S+A / Union) appears verbatim on `index.html` §4f and `periodicity.html` §7. The 13-library NP+DI table is duplicated. Pick one canonical home (recommend `periodicity.html` — it's the evidence document) and let the walkthrough show the headline row + a "Detail on the periodicity page" link.
4. **The walkthrough's §10 (Reverse Proxy Myth) is now redundant** with §9a (WAF Dividend) and the Operational Model's WAF-as-spackle section. It deserves to become a sub-callout under §9, or move to the Operational Model entirely.

The rest of this report walks through assessment, restructuring delta, dashboard delta, and architecture in more detail. Daily scan at the end.

---

## 1. Assessment of the Periodicity Analysis (current HEAD)

### 1.1 Is the NP+DI methodology sound?

**Mostly yes, with three structural soft spots that earlier passes flagged and one new wrinkle from the §15 EPSS rebuild.**

What's strong:

- The **two-condition definition** is mechanical and falsifiable: NP from a named manifest list, DI from a published CWE set. The cve-reference page makes per-CVE classification auditable end-to-end. A reviewer who disagrees with a specific call can re-run the filter on their own data without arguing about a black box.
- **The widened DI set** (auth bypass via input manipulation: CWE-287, -289, -306, -345, -693, -863, -1321) is correctly justified on the trust-boundary principle that's articulated in CLAUDE memory and re-stated on the periodicity page. The widening's optical risk (looks like goalpost-moving) was earned: pass 5 flagged the disclosure as inadequate, and the walkthrough §3b table now shows the auth-bypass widening as a separate banded section with an explicit note. That's the right disclosure shape.
- **CWE-444 inclusion is well-handled.** Without it, Netty would have zero NP+DI triggers in 12 months. Including it surfaces a real exploitation class — request smuggling — that other CWEs miss.
- **The §15 EPSS rebuild is the strongest new content in the analysis.** The day-0/day-7/day-30 comparison cleanly answers the "is structure-based filtering really needed if EPSS exists?" critique that any sophisticated reviewer would raise. The "model is on average 34.7 days faster than EPSS ≥ 0.10 / 131 days faster than EPSS ≥ 0.50" framing is honest, reproducible (`scripts/compute_epss_marginal.py` → `data/epss-marginal.json`), and operationally meaningful. The "EPSS marginal cost on top of the model" table — at EPSS ≥ 0.50, NP+DI absorbs 41 of 44 would-be EPSS triggers — is the cleanest argument I've seen for why the structure filter is *complementary* to EPSS, not a competitor.

What's still soft:

- **CWE classification is the filter's single largest exogenous dependency.** The 7-year backtest's three NP+DI-raw misses (Ghostcat tagged CWE-269, Tomcat partial-PUT tagged CWE-502, ActiveMQ Jolokia tagged CWE-20) are all upstream-CWE-quality failures, not filter-logic failures. The DQ layer is the proposed mitigation; it does close all three. But the dependency itself is real and worth disclosing prominently rather than as a §4f-table footnote. Consider a top-of-§3 "what this filter depends on" callout: NP classification (analyst judgment), DI CWE set (versioned, currently v1.2), upstream CWE quality (out of our control; DQ rescue closes the gap). This is pass 5's recommendation; still not implemented.
- **NP classification is more judgment-call than the page admits.** Pass 6 §1.1 nailed this: classifying `socket.io`, `passport`, `httpclient5`, `requests`, `urllib3` as NP while `pg`, `redis`, `ioredis`, `pymongo` are non-NP collapses two distinct ideas — "speaks an internet-attacker-reachable wire protocol" vs. "sees attacker-controllable input on its primary code path" — into one "NP" label. The deployment argument ("RESP/Postgres-wire isn't attacker-controlled") is real but it's a deployment claim, not a classifier claim. The honest position is: NP captures *typical-deployment* attacker reachability, and that's why the cve-reference page exists as the auditable cut. A sentence-level concession in §3a or a footnote on the cve-reference page would close this.
- **Patch-event merging window (7 days) is a knob.** Going to 0/3/14/30 days materially moves the hacker-vs-NP+DI patch-event count, especially around 2021's Log4Shell/XStream/jackson cluster and 2022's deserialization avalanche. A small sensitivity table (0d/3d/7d/14d → patch-event count for each strategy) would close the curmudgeon's "you picked the number that flatters the story" critique. Periodicity page §7 has room for this; not yet present.
- **EPSS comparison's pre-EPSS-coverage handling is now better disclosed but should be flagged in the headline.** Two of eight in-scope exploited CVEs (Ghostcat 2020, Tomcat CGI 2019) predate EPSS coverage. They're scored 0/2 against EPSS in the caught-before-exploit tally, which is fair-but-loaded. The "average 34.7 days faster" headline is computed on the n=6 with EPSS coverage, which is correctly disclosed in the methodology paragraph but doesn't show up in the hero stat. A reader skimming the headline could easily mis-attribute the 34.7-day lead. Not a fix-today item, but worth a parenthetical on the headline.

### 1.2 Is the cross-framework validation convincing?

**Yes for what it claims, with the asterisk that pass 6 named correctly: it's corroborating, not validating.**

The 14-14-14 convergence (Spring/Node/Django all hitting 14 distinct all-C/H trigger dates in 12 months) is a striking ecosystem-portability signal. The reduction profile (64–86%) holds across Maven/npm/PyPI/Java-second-stack-Netty. The Django "honest hardest case" framing earns credibility — the page says explicitly that Django's 67–71% is the floor, not the headline.

The asterisk: **the four manifests were authored by the same analyst.** The 7-year real-enterprise-Java backtest is the cleaner test because the manifest is an actual production dependency list. The synthetic stacks demonstrate that the result *generalizes* across ecosystems and frameworks; the 7-year backtest demonstrates that it *holds against ground truth*. The current ordering (synthetic 12-month → 7-year backtest as supporting case study) is upside-down for credibility. Pass 4 §11 and pass 6 §1.2 made this point; it's still true. Lead with the 7-year backtest; treat the 12-month synthetic stacks as "and here's why this isn't a Java-and-Tomcat artifact."

Periodicity §3 (Cross-Framework Headline) was reordered yesterday (commit `b1b3966` puts Sample Stacks before Headline) which is good visual hierarchy — but the substantive ordering decision (12-month synthetic vs. 7-year backtest first) is unchanged.

### 1.3 Is the OS chaining / kill-chain framing correct?

**Directionally yes. The headline number is still inflated, but the walkthrough §7 acknowledges this.**

Structural finding ("OS layer doesn't drive emergency rebuild cadence under either NP+DI or hacker S+A; monthly container refresh controls blast radius") is sound. NP+DI = 0 on the cleaned OS-component manifest in 12 months is a clean negative result.

The 21-LPE / 76%-reduction headline is the live problem:

- **Walkthrough §7 (`index.html` line 663–675):** correctly cleaned. Now reads "10–12 LPE-relevant CVEs (chaining risk, cleaned)" with the noise-cleanup callout. Headline KPI tile shows ~18 OS-component C/H cleaned and 10–12 LPE-relevant. Good.
- **Periodicity page §The OS Layer (`periodicity.html` line 595–637):** keeps both numbers in tension. The hero KPI still shows "21 LOCAL vector (privesc)" at line 583. The cadence-comparison table at line 633 still shows monthly = 5 / 76% reduction. The footnote at 636 says "the cleaned LPE-relevant figure is closer to half." Recommendation: the cadence-comparison table headline should be the cleaned 60–70% reduction, with raw 76% in the footnote — match the walkthrough.
- **Dashboard "OS Container Privesc Accumulation" chart:** still 21 on the y-axis, no caveat. Same fix needed.

This is yesterday's recommendation #1 still alive.

### 1.4 Does the EPSS / external-validation analysis hold up?

**Strongly. This is the analysis's most defensible content right now.**

The reframing of EPSS as "complementary, not competitive" is the operationally correct take. The day-0/day-7/day-30 comparison table cleanly shows that the structure filter wins where it matters (disclosure day) and EPSS catches up where it can (in retrospect). The marginal-cost-on-top-of-the-model table is the kill shot: at EPSS ≥ 0.50, only 3 of 44 EPSS-flagged events aren't already absorbed by an NP+DI rebuild trigger; at NP+DI+DQ, only 1 of 44.

The "never worse than EPSS" framing in the §7 worked example callout (Tomcat HTTP PUT 2017 pair) is correctly defensive: the structure filter B-tiers the pair, supplements (floor sweep + cadence + threat intel) absorb them, EPSS would not have done better in the disclosure-to-exploitation window because the pair sat at low scores for years before the KEV add. This is the right framing — *structure filter + supplements ≥ EPSS, on every event* — and it's defensible in a way "structure filter alone" wouldn't be.

What I'd still tighten:

- The §15 EPSS section is now ~7 cards long. It was 3 cards a week ago. Each card adds value but the surface area is getting hard to skim. Consider a 1-paragraph summary callout at the top with the headline number, before the methodology unfolds.
- The pre-EPSS-coverage caveat (Ghostcat 2020, Tomcat CGI 2019) needs a single-sentence parenthetical in the hero callout, not just buried in the methodology paragraph. Headline should read "model catches the same CVEs as EPSS, but on average 34.7 days faster (vs EPSS ≥ 0.10) and 131.0 days faster (vs EPSS ≥ 0.50, n=6 with EPSS coverage)" or similar.

### 1.5 Devil's-advocate: what could undermine the conclusions?

The user-preferences instruction was "think about the other side of the argument too." Here are the cleanest arguments against the analysis as it stands:

1. **The 11/13 union catch is still presented as the model's score, not the union of two strategies.** A skeptic can correctly point out that NP+DI+DQ alone is 9/13 and Hacker S+A alone is 10/13 — and "union" as a strategy means "run both and merge the sets," which adds operational cost. The walkthrough §4f honestly discloses this in the table, but the §4a hero KPI ("11/13 7-year backtest catch (union NP+DI+DQ ∪ Hacker S+A)") could be misread as "the model catches 11/13," when really the model has two operationalizations and you only get 11/13 if you run both. This is presentation, not substance — a one-word fix to the KPI label ("11/13 if you run both methods") would close it.
2. **The "supplements catch the 2017 pair" argument is post-hoc.** The Tomcat HTTP PUT 2017 disclosure-to-KEV gap of 1–5 years is real and the floor-sweep retrospective is correct, but the framing — "any Cat 1/2 team would have rolled past these on normal cadence" — is doing a lot of work. A hostile reviewer could fairly say "you're claiming credit for a hypothetical patch path that an actual 2017 team wouldn't have run." The walkthrough §4f callout is honest about this ("the model is the structure tests *and* the supplementary controls together"), but the "B-tier handled by supplements" framing presupposes the supplements exist and run. Recommendation: somewhere in §4f or §9, add an explicit "this assumes a Cat 1/Cat 2 team with floor-sweep discipline; a Cat 3 team with strict version-pinning gets a different result" sentence. The Operational Model page partially covers this but the walkthrough should own the caveat.
3. **The "structure filter is never worse than EPSS" claim depends on the supplements working.** Same shape as #2. EPSS has the property that it's a single number you can threshold. The model has structure + DQ + hacker + supplements + threat intel. "Never worse than EPSS" requires all five to fire. That's a fair claim if you actually run all five, but it's also a much taller stack than EPSS. A skeptic's pushback: "you're comparing your full defense-in-depth stack to one of EPSS's variables." A truthful response is that EPSS is also assumed to operate inside a larger defensive context (you don't deploy EPSS without patch infrastructure either), so the comparison is fair if both are situated in their full operational context. Worth saying explicitly.
4. **The 14-14-14 convergence is suspicious in a *good* way the page doesn't claim.** All three frameworks producing 14 all-C/H trigger dates in the same window has a roughly 1-in-100 base rate against random alternatives. Either there's a genuine common-cause structure (mature ecosystems converge on a similar disclosure rate at similar dependency-tree size — what pass 6 hypothesized) or the manifest selection is filtering toward that number. Adding a 5th-or-6th synthetic manifest from a less-canonical ecosystem (Rails? Go? Phoenix?) and showing whether the 14 converges or scatters would either strengthen the finding or expose the artifact. Not urgent, but a credibility-multiplying experiment.
5. **The watch-list hit rate (5/14 promoted to KEV in ~6 weeks) is the prospective validation but it's not sized as such.** The walkthrough §11 watch list is the live experiment that validates the filter's predictions against actual KEV adds. 5 of 14 entries promoted with no false-positive class (every promotion was an HTTP-parsing-adjacent network parser) is the cleanest signal that the filter generalizes prospectively. This deserves a top-of-page hero stat, not a buried table. The dashboard especially undersells this.

### 1.6 What's new since yesterday's review (commit `b6059ca`)

Yesterday's review applied. The 4 obvious fixes (commit `6df96ed`) landed. Today's HEAD is 24 commits ahead, with the substantive changes:

- **`§15 EPSS` rebuild** (commits `a6a210c`, `1eb5328`, `88aca46`, `ce01010`) — Hacker S+A row added to operational comparison; days-faster + caught-before-exploit headline; daily re-scoring framing; "14 unique" KEV table scope clarification; 30-day patch cycle removed from EPSS narrative.
- **Operational Model rework** (commits `e813286`, `86d052e`, `dc3fcb6`, `171c9a5`) — internet-vs-internal example added to BAU; floor-sweep clarified as completeness-not-just-speed; hero/exec summary box replaces "On this page" TOC; §5 moved before §3 (the 14-emergencies math now comes after the Cat 1/2/3 framing it depends on).
- **Visual unification** (commits `2593b66`, `345a2d1`, `8249a24`) — evergreen and build-mechanics converted from dark theme to warm-light style with sidebar nav. Project visual identity is now consistent across all 6 pages.

Nothing in this delta moved the analytic substance. The work is now in the polish-and-converge phase, which is exactly where it should be.

---

## 2. Walkthrough Restructuring Recommendations

The brief's mental model — "the walkthrough is still the original observational analysis; recommend a section outline" — is wrong against today's HEAD. The walkthrough has been restructured. The remaining recommendations are tightening, not surgery.

### 2.1 Current section structure (already good)

```
1.  The Problem                                       — opener, three-app-profiles framing
2.  Where Exploits Land                               — observational analysis (stack layers, NP, libraries)
2a-c.  Stack Layer Rates / Network-Parser Signal / Libraries Deep Dive
3.  The Threat-Based Prioritization Model             — core exposition: NP+DI structure test + hacker discriminator
3a-e.  NP+DI / DI CWE Set / Falsifiability / Hacker / Churn cost
4.  Does It Actually Work? Cross-Framework Validation — 14-14-14 + 7-year backtest
4a-f.  14-14-14 / Strategy comparison / Silence windows / Catches / Django weak / Real Java manifest
5.  Why Most Criticals Don't Get Exploited            — survivorship analysis
6.  Time-to-Exploit Compression                       — 251d→11d→3d
7.  Land & Expand                                     — kill chain / OS layer / privesc accumulation
8.  External Validation                               — EPSS, KEV, ExploitDB, Nuclei, Metasploit + WAF defensibility
9.  Operational Response by Estate Maturity (Cat 1/2/3) — links to Operational Model
10. The Reverse Proxy Myth
11. Exploit Watch List
12. Caveats
```

This is a coherent argument: problem → observational evidence → model → validation → operational response → live experiment. Don't restructure it.

### 2.2 What to keep, cut, move

**Keep as-is:**

- §1 (problem framing, three-app-profiles), §2 (observational evidence), §3 (model exposition), §4 (cross-framework + 7-year), §7 (kill chain — with the noise-cleanup applied), §8 (external validation), §9 (operational response).
- The "How to read this site" 5min/30min/verify/live/build-mechanics/AI-angle table at the top. This is the right onboarding pattern.
- §11 watch list. This is the live validation experiment.

**Tighten:**

- **§4f (Real-World Case Study).** The strategy-efficiency table and the 13-library NP+DI table are now duplicated on `periodicity.html` §7. Either:
  - Keep the headline summary row + "Detail on the periodicity page" deep link (lighter walkthrough).
  - Or trim to the strategy table only and move the per-library detail to periodicity.html.
  Yesterday's review made this recommendation; not yet applied.
- **§5 (Why Most Criticals Don't Get Exploited).** The survivorship-bias content is good but it now reads as standalone observational content. Re-anchor as "what the filter correctly excludes" — a §3-aligned restatement of the same data, not a separate thesis. The opening sentence could be: "The threat-based filter excludes ~93% of C/H CVEs. Here's why that's defensible."
- **§6 (Time-to-Exploit).** The 251d→11d→3d framing is striking and should stay, but the implication "30-day patch cycle is broken" was the *old* argument for emergency response. The new argument (NP+DI + hacker S+A reduce emergency events to 2–6/year, supplements absorb the rest) makes the time-to-exploit data into supporting evidence for "you can't outpatch attackers on volume; you have to triage." Re-anchor §6 as supporting §3e ("hidden cost of not filtering"), not as a standalone section.
- **§8a (WAF defensibility).** This is now a strong sub-section. Consider promoting it to a top-level §8 successor or merging with §9a (WAF Dividend) to avoid two WAF passes in the same page.
- **§10 (Reverse Proxy Myth).** Now redundant with §9a + Operational Model §wafs. Demote to a callout in §9a, or move to Operational Model entirely.

**Cut:**

- The "Use this tomorrow" checklist at the end of §9 (lines ~810–820) duplicates content the Operational Model page now owns. Either link to Operational Model or trim to the 3-bullet headline.

### 2.3 Where the periodicity findings fit (already integrated)

- §3 introduces the model.
- §4 says "and here are the cross-framework results" with the 14-14-14 + 7-year backtest.
- §8 says "and here's how it compares to existing exploitation signals (EPSS, KEV, etc.)."

This is already the right integration. The periodicity page is the deep-dive evidence document; the walkthrough is the argument.

### 2.4 The "zero-miss" framing — one final pass

Yesterday's review flagged this. Today's status:

- Walkthrough §4b honest framing: ✅ in place ("N=1 doesn't differentiate strategies from random").
- Walkthrough §4a hero KPI: now reads "11/13 7-year backtest catch (union NP+DI+DQ ∪ Hacker S+A)" — better than "zero misses" but the "union" caveat is in the label only. Consider: "11/13 caught directly, 2/13 absorbed by supplements" to make the supplements role explicit.
- Walkthrough §9 quick-checklist: still says "track your filter's hit rate over 6 months — it should produce zero misses." This is now contradicted by the §4f 7-year data (7 misses in Spring+Django, all CWE-misclassification or out-of-NP-scope). Change to "it should produce few misses, all of them in the documented blind-spot patterns."
- Walkthrough §12 Caveats: still says "12 months of zero misses is strong but not conclusive." Reword to "12 months of N=1 is statistically uninformative; the 7-year backtest is where scoring happens."
- Dashboard line 166: "zero misses — no filtered-out CVE has appeared in CISA KEV." The strict reading is 12-month-window-only, but the dashboard banner doesn't say 12-month. Either scope it ("zero misses in the 12-month synthetic-stack window") or replace with the 7-year backtest result (11/13 union, with supplements absorbing the residual 2).

### 2.5 Periodicity page should remain separate

Confirmed against today's HEAD. The architectural pattern — walkthrough = argument, periodicity = evidence, cve-reference = audit trail, dashboard = live data, build-mechanics = how-to, glasswing = intel assessment — is the right shape. Don't fold periodicity back into the walkthrough.

---

## 3. Dashboard Updates

### 3.1 What to fix

1. **Line 166 banner:** scope or replace the "zero misses" claim. (Yesterday's recommendation; still live.)
2. **OS Container Privesc Accumulation chart:** annotate the y-axis with the cleaned 10–12 figure or replace 21 with the cleaned number. Either approach beats the current uncaveatted 21.
3. **Three Response Lanes section title** (line 329): the rename from "Three-Tier Patching Model" already happened — good. But the card content still describes the trigger axis under "tier" framing rather than the lane framing the title suggests. Recommend renaming the cards: "Triggered" / "Cadence" / "Cycle" (matching the lane framing), and let the Cat 1/2/3 estate-maturity dimension live on the walkthrough §9 + Operational Model.

### 3.2 What to add

1. **Watch-list hit-rate KPI tile.** "5 of 14 promoted to KEV — Marimo, SharePoint, ActiveMQ, Adobe Acrobat, Defender BlueHammer" — the prospective-validation surface that's currently undersold. This is yesterday's #7 recommendation and remains the cleanest single addition.
2. **EPSS-marginal hero stat.** "At EPSS ≥ 0.50, NP+DI absorbs 41 of 44 would-be EPSS triggers" or similar. The EPSS section on `periodicity.html` is too good to be invisible from the dashboard.
3. **Day-0 catch comparison.** A 4-bar chart: NP+DI raw / NP+DI+DQ / Hacker S+A / EPSS ≥ 0.10 day-0 catch on the 7-year backtest. Single chart, ~4 bars, kill-shot framing.

### 3.3 What's now stale / OK to remove

- The "0 misses in 12 months" line in line 166. Either scope to the 12-month sample or replace with 7-year.
- The "Three-Tier Patching Model" framing was already retired from the section title — good. The card content needs the same treatment.

### 3.4 What to leave alone

The dashboard's primary value is fast-loading data charts that auto-refresh daily. It should not become a second walkthrough. Keep the existing layer rates, HTTP-parsing lift, TTE, CWE families, ransomware, top products, and searchable KEV table. The cross-framework chart and OS privesc chart are the right additions; don't add more periodicity charts.

---

## 4. Cross-Page Architecture

### 4.1 Page roles (recommended; mostly already in place)

| Page | Role | Audience |
|---|---|---|
| `index.html` | The argument. Problem → model → validation → operational response. | New reader, sets the case. |
| `periodicity.html` | The evidence. Reproducible cross-framework + 7-year backtest with supporting tables and per-event reasoning. | Skeptical reader who wants to verify or adopt. |
| `cve-reference.html` | The audit trail. Per-CVE classification with WAF defensibility column. | Reviewer, adopting team. |
| `dashboard.html` | The live scorecard. Daily-refreshed data. | Operational reader, recurring visit. |
| `build-mechanics.html` (Operational Model) | The how-to. Cat 1/2/3 estate maturity, BAU vs floor sweeps, WAFs as bridge, get-newest builds. | Implementer. |
| `glasswing.html` (Mythos) | The intelligence assessment, labeled speculative. | Reader interested in the AI-vulnerability-research angle. |
| `evergreen.html`, `osv-exploitation.html` | Scratch-status auxiliary analyses. | Internal / curiosity. |

This structure exists. The work is making sure each page stays in lane — the §4f duplication between walkthrough and periodicity is the most visible offender.

### 4.2 Front-door experience

The walkthrough is the front door. The "How to read this site" table is the right onboarding pattern and should stay. Two improvements worth considering:

- **A "what's new since last quarter" callout** for repeat visitors. The site presents as a single document but is actually a moving analysis with weekly substantive updates. A 2–3 sentence "since April 21: added DI auth-bypass widening, hacker discriminator, EPSS day-0 comparison" would help repeat readers know what's worth re-reading.
- **A versioning indicator on the model.** The "threat-based prioritization model v1.2" with a CWE-set changelog (pass 5 §1.1's recommendation) is still missing. Versioning the model is the difference between "evolving analysis" and "p-hacking." Pass 5 was right that this is a 30-minute edit.

### 4.3 Navigation

Top-nav (Overview / Periodicity / Operational Model / Evergreening / Mythos / Dashboard / CVE Reference) is consistent across all pages now. Keep.

The walkthrough's left sidebar at 12 sections is at the upper end of scan-friendly. After the §6 → §3e fold and §10 → §9a callout proposed in §2.2, the sidebar would have 10 sections, which is better.

---

## 5. Summary of Recommended Actions (ordered by impact)

1. **Scope or replace the "zero misses" claim on the dashboard banner.** Five days unaddressed; pass 5 had it as "highest urgency, ~5 min, must-ship-today."
2. **Use the cleaned LPE figure (~10–12, 60–70% reduction) as the headline on `periodicity.html` §The OS Layer cadence-comparison table and on the dashboard chart.** Walkthrough already cleaned; the other two surfaces still leak the inflated number.
3. **Trim walkthrough §4f.** Move the per-library NP+DI table to periodicity.html; keep the strategy table + headline row + deep link.
4. **Re-anchor §5 and §6** as supporting §3, not as standalone theses. §6 in particular is the time-to-exploit data that motivated the original "fast triage" need; its current standalone framing is orphaned.
5. **Fold §10 (Reverse Proxy Myth)** into §9a or move to Operational Model.
6. **Add a watch-list-hit-rate KPI tile to the dashboard** (5/14 promoted to KEV). The cleanest prospective-validation surface and currently undersold.
7. **Add the auth-bypass-widening CWEs (287, 289, 306, 345, 693, 863, 1321) to the §3b DI table explicitly** — they're now in a banded section but the formatting could be cleaner.
8. **Add a worked hacker-tier example** to §3d (Spring4Shell as S/A, Tomcat HTTP PUT as B, Multer DoS as D). The rubric is described abstractly; concrete examples would land it.
9. **Publish a CWE-set versioning changelog** (pass 5 §1.1). Versioning the model is what stops the "looks like p-hacking" reading of the DI widening.
10. **Add a sensitivity table for the 7-day patch-event merge window** (0d/3d/7d/14d). One paragraph in periodicity §7. Closes a curmudgeon objection cheaply.

The walkthrough should NOT be restructured. It's converged. The work is tightening, deduplication, and updating the headline numbers that still inherit the overstated version.

---

## 6. Daily Scan (2026-04-28)

### KEV
- catalogVersion **2026.04.24**, total **1,583**, April KEV **28**. **Five-day catalog freeze** since 2026-04-24 (the 4-entry batch with D-Link, Samsung, SimpleHelp pair). This is the second-longest dry spell of 2026 — within normal range (longest is the early-April 8-day stretch). No new entries in the last 24 hours.
- Watch-list hit-rate stable at **5 of 14 promoted to KEV** (Marimo CVE-2026-39987, SharePoint -32201, ActiveMQ -34197, Adobe Acrobat -34621, Defender BlueHammer -33825). 9 still WATCHING:
  - Server: Thymeleaf SSTI pair (-40477, -40478), wolfSSL pair (-5194, -5501), n8n Ni8mare (-21858), Cisco ISE cluster (-20180, -20186, -20147), Cisco Webex (-20184).
  - The Cisco ISE cluster + Cisco Webex SSO are the four probable-participant-self-scan entries (Cisco is a Glasswing participant). They've been WATCHING since mid-April. Cisco SD-WAN's 46-day exploitation-to-KEV gap suggests these could land in KEV around late May.
  - n8n Ni8mare has been WATCHING for 9 days now. Horizon3's "zero customer impact" finding from 2026-04-19 is becoming the cleanest piece of disconfirming evidence for the "PoC → KEV in days" heuristic — public CVSS 10.0 with a working PoC and ~100k exposed instances per Cyera, but no exploitation telemetry has accumulated.

### NVD volume
- April MTD = 5,371 (day 28 of 30). Day-over-day +197 CVEs, on the running April-2026 average of ~192/day. Extrapolation 5,755 (was 5,748 yesterday).
- April will close ~9% below March (6,304) and within the Q1 churn band (4,808–6,304). **Twenty-eight days of the post-Glasswing-launch volume run continues to argue against the "AI is flooding CVE" framing.** Counter-argument continues to live: NVD assignment latency 4–8 weeks means a Mythos surge from April could still be in the publishing pipeline. The data cannot distinguish "no surge" from "surge in pipeline" until mid-to-late May. April 9 Tomcat batch (7 CVEs all-NP, 6 of 8 DI) is the only suggestive signal in the window so far, and even that is bounded by "looks like coordinated release of Mythos-Preview-found bugs" rather than confirmed.

### Glasswing / Mythos
- Glasswing CVE count holds at **283** (271 Firefox 150 / MFSA 2026-30, 9 wolfSSL, 1 each F5 NGINX Plus / FreeBSD / OpenSSL). No new participant products surfaced.
- Claude-credited known: **6** (CVE-2026-4747 FreeBSD NFS autonomous, CVE-2026-5194 wolfSSL cert validation Mythos-Preview-assisted, CVE-2026-5588 Bouncy Castle Carlini+Claude, plus three Firefox 150 entries CVE-2026-6746/6757/6758). No new credits in 24h.

### Glasswing-participant cross-check (today)
- No new attribution-shaped CVEs in the 24h window.
- No new entries qualify for the probable-participant-self-scan table beyond the existing four Cisco entries.

### Notable / non-routine
- **The watch-list cadence (5 promotions in 6 weeks) is now stable enough to surface as a dashboard KPI** — recommendation #6 above. This is the cleanest prospective-validation surface the project has and currently it's only visible in the table-row view on `index.html` §11.
- **The Tomcat batch (April 9–15) continues to look like the only April datapoint that suggests Mythos influence.** All 7 events were NP-and-DI, exactly the cluster shape the model would predict if Mythos-Preview is being used to find HTTP-parsing bugs. But "looks like coordinated release" isn't proof — the same shape would result from any focused fuzzing campaign, AI-assisted or not.
- **No KEV-level signal that overturns the cumulative pattern.** April KEV remains dominated by enterprise-edge products (Fortinet, Ivanti, SharePoint, Exchange, ActiveMQ, NetScaler, D-Link, Samsung, SimpleHelp, Cisco SD-WAN). The HTTP-parsing-adjacent share is ~50% of April KEV, in line with the long-run ~47% baseline.

---

*End of review report. Recommendations are advisory; no HTML edits made by this run per the task brief instructions. Today's pass overwrote `periodicity-review.md` (was commit `b6059ca`, 2026-04-27); prior pass5/6/7 reports remain at their existing paths.*
