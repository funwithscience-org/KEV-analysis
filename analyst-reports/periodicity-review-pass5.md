# Analyst Review — Fifth Pass (2026-04-24)

This is the fifth-pass review of the periodicity analysis and integrated walkthrough/dashboard/reference set, running against HEAD commit `3191334` (11 commits ahead of where the fourth pass closed). I'm deliberately writing this as its own file rather than appending to `periodicity-review.md` — it is long enough to warrant separation and it reviews substantial new work (DI widening, independent reviews, Glasswing extraction, layer classifier rebuild) that sits on top of everything the first four passes recommended.

## 0. TL;DR

The last 30 hours changed four things that matter:

1. **The DI CWE set was widened** to include auth bypass via input manipulation (CWE-287, 289, 306, 345, 693, 863, 1321). This added 4 events to the 12-month synthetic backtest and 5 events to the 7-year Java backtest. Reduction rates dropped across the board: overall 73% → 67%, Spring specifically 73% → 59% → 64% (after layering the text-bug reconciliation). The author's position is that these CVEs were *miscategorized DI* and adding them *corrects an omission*, not that they represent goalpost-moving. I largely agree, but the optics are terrible in the absence of a CWE-set versioning disclosure — see §2.
2. **Glasswing/Mythos content was extracted from the dashboard to `docs/glasswing.html`.** This is the right call — the Curmudgeon reviewer flagged it as "intelligence analysis dressed as data," which is exactly what it was. Dashboard is cleaner and more defensible now. Cross-page nav was updated on all five pages and the Glasswing page now carries a "speculative analysis" label. **Biggest win of the week.**
3. **The independent four-reviewer pass completed 10 sub-passes.** Review findings in `REVIEW-FINDINGS.md` document confirmed bugs (5 text-level, fixed in commit `b190ce3`), structural critiques (circularity, survivorship bias, temporal fragility, AI-scan-tier reproducibility), and a prioritized punch list. Overall grade **B** — *"solid operational analysis, adopt as triage accelerator with conditions."* Most of the confirmed bugs were closed in the same day. This is a big credibility upgrade; see §1.4.
4. **Two watch-list CVEs were promoted to KEV:** CVE-2026-33825 (Windows Defender "BlueHammer") on 2026-04-22 and CVE-2026-39987 (Marimo pre-auth RCE) on 2026-04-23. Both had been flagged on the list 4 days earlier with `weaponized` maturity. **This is a 2/2 prospective-prediction hit rate in 96 hours** and it's the single most under-promoted piece of evidence in the whole repo. See §3.

Net assessment: the analysis is meaningfully stronger than 30 hours ago. The DI widening is defensible but poorly disclosed. The zero-miss overclaim I flagged in pass 4 §13.2 item 1 **still hasn't been fixed** in the dashboard copy. The 2/2 watch-list KEV confirmation should be promoted to a hero stat.

---

## 1. Assessment of New Work Since Pass 4

### 1.1 DI widening — defensible, poorly disclosed

Commit `d4d8f65` adds seven CWEs to the DI set: **287** (improper authentication), **289** (authentication bypass by alternate name), **306** (missing auth for critical function), **345** (insufficient verification of data authenticity), **693** (protection mechanism failure), **863** (incorrect authorization), and **1321** (prototype-pollution). The `data/di-reclassification.json` file lays out the rationale per-CVE with explicit `included` / `excluded` flags — that's unusually rigorous work for what could have been hand-wave. The exclusion logic ("CVE-2021-22119 excluded because CWE-400 DoS is the primary mechanism, CWE-863 is a secondary consequence") shows the author actually thought about the false-positive floor.

**Why the widening is the right call:**

- The security-industry mental model of "injection" has always been broader than OWASP's A1 (SQLi/XSS/etc.). CWE-22 path traversal is an injection (path-as-data); CWE-863 authorization bypass via crafted input is structurally the same pattern (security-decision-as-data). Narrowing DI to only "attacker writes code into the parser" missed a class of bugs that operationally lived in the same emergency-rebuild tier.
- The di-reclassification.json file makes the change auditable. A reviewer can verify that (a) the added events are genuine injection-family, not retroactive cherry-picks, and (b) the exclusion criteria are consistently applied.
- Spring Security CVE-2022-22978 (the RegexRequestMatcher bypass) is the canonical example — operationally every Spring shop treated it as emergency-grade in 2022 and the filter should match that intuition. Excluding it on narrow DI-definitional grounds was the original wrong call.

**Why the optics are terrible anyway:**

- The Curmudgeon review explicitly flagged this: *"Widened DI (adding auth bypass) looks like goalpost-moving."* It does. A reader who arrives at the page cold sees "the filter was published April 21 with 73% reduction. Two days later the filter was widened and now shows 67% reduction with 4 more triggers." Without explicit disclosure of *why* the CWE set changed and *what changed between versions*, this reads like the researcher noticed the filter looked too strict and relaxed it to catch more real bugs. The charitable interpretation (miscategorization correction) and the cynical interpretation (goalpost-moving to preserve zero-miss) produce identical data.
- The fix is not to not widen the filter. It's to **publish a CWE-set versioning changelog** that names: (a) what's in the set today, (b) what was in the set before, (c) the date of each change, (d) the rationale for the change, (e) the diff in backtest numbers. This is what pass 3 §10.4 recommended and it's still not done. As long as the DI set is evolving without a public changelog, hostile reviewers will read each widening as p-hacking.
- The current footnote-level disclosure in periodicity.html (around line 699, mentioning "without the CWE-444 addition, this stack would have had zero triggers") is too easy to miss. Pass 4 §13.2 made this recommendation; it's now more urgent given a second widening has landed.

**Recommendation for the walkthrough:**

Add a §6d (CWE Set Versioning & Changelog) between §6c (defining DI) and §7 (cross-framework validation). One paragraph, two tables:
1. Current DI CWE set with class grouping (command injection, template injection, auth bypass, etc.).
2. Versioning log: `v1.0 2026-04-21 initial` → `v1.1 2026-04-22 +CWE-444` → `v1.2 2026-04-23 +CWE-287/289/306/345/693/863/1321`.
3. Policy statement: "The DI CWE set is versioned. New CWEs are added when they represent genuine network-parser direct-injection patterns that our review identifies as within-scope. Each change is dated, justified, and re-runs the validation backtest."

This is a 30-minute edit that removes the single biggest live critique of the filter.

### 1.2 Zero-miss overclaim — STILL NOT FIXED

Pass 4 §13.4 item 1 listed this as *"highest urgency, ~5 min, must-ship-today."* It is now 30 hours later. Current state:

- **`docs/dashboard.html` line 161:** *"reduces rebuild-trigger dates by 64–86% with zero misses — no filtered-out CVE has appeared in CISA KEV."* **Still the overclaim.**
- **`docs/index.html` line 177 (TL;DR):** *"cut emergency rebuilds by 64–86% across three ecosystems with zero misses in 12 months."* Still the overclaim, and it's literally in the TL;DR.
- **`docs/index.html` line 600 (§9 translation box):** *"Zero misses across 113 non-triggers."* Still the overclaim.
- **`docs/index.html` line 686 (§10 guidance):** *"your filter's hit rate… should produce zero misses."* Still prescriptive overclaim.
- **`docs/index.html` line 920 (§14 caveats):** *"Twelve months of 'zero misses' is strong but not conclusive."* At least this one hedges.
- **`docs/periodicity.html` line 541, line 685:** Both still frame as zero misses across 12 months / 113 non-triggers.

The 7-year real-enterprise-Java backtest (§7d in the walkthrough) **does** disclose the 3 CWE-misclassification misses (CVE-2020-1938 Ghostcat, CVE-2025-24813 Tomcat deserialization, CVE-2026-34197 ActiveMQ Jolokia). But the three most-visible pages (dashboard hero, walkthrough TL;DR, walkthrough §9) all contradict that disclosure by headlining zero-miss.

This is a credibility problem. If a reader reads the dashboard first (the page a CISO actually lands on) and then finds §7d's 3-miss disclosure, the natural conclusion is that the dashboard copy is wrong and the walkthrough copy is right, and by extension that the other dashboard numbers may also be spun. The fix is the same 5-minute copy edit it was 30 hours ago:

- **Dashboard line 161:** Replace with *"reduces rebuild-trigger dates by 64–86% with zero exploitation misses within correctly-classified advisories. Three misses across 7 years were traceable to NVD CWE misassignment; all are catchable by an automated CWE-validation pass. [See §7e →]"*
- **Walkthrough line 177 (TL;DR):** Replace *"with zero misses in 12 months"* with *"no exploited CVE in that window was missed by the filter; three historical misses across 7 years of backtest trace to NVD CWE misassignment and are addressable by an AI safety-net pass."*
- **Walkthrough §9 title:** Retitle from "External Validation: The Zero-Miss Window" to "Cross-Validation Against Five Exploitation Databases." Keep the analytical content.
- **Walkthrough line 600:** Replace *"Zero misses across 113 non-triggers"* with *"No non-trigger appeared in KEV, Metasploit, or accumulated significant exploitation evidence."*
- **Walkthrough line 686:** Replace *"should produce zero misses"* with *"should approach zero exploitation misses — track CWE-classification disagreements between your filter and live NVD assignments as a leading indicator of the misclassification failure mode."*

Until this is done the dashboard and walkthrough are internally inconsistent on the filter's single headline stat. That's a worse position than the analysis deserves given how strong the actual 5-exploited-and-caught / 3-misclassified-and-specifiable result is.

### 1.3 Layer classifier rebuild (ransomware 191 → 186) — the right cleanup

Commit `0c430b9` replaces ratio-estimation with a reproducible first-match-wins classifier written as `data/kev-classifier.py`. Snapshot file pinned (`data/kev-snapshot-2026-04-23.json`); classifications file pinned (`data/kev-layer-classifications.json`). Per-entry classifications expose vendor, product, layer, ransomware flag. This is exactly the architectural change the Data Freak reviewer asked for (§3 of REVIEW-FINDINGS.md).

Two small observations:

- **First-match-wins rule ordering matters and is underspecified.** The CLASSIFIER.md preamble notes: *"Very specific product names are checked before generic vendor names; platforms/runtimes before broad OS detection."* That's the right heuristic, but it means rule order is load-bearing — a rule reordering could shift categorizations without changing any data. Worth adding a test file (`test_kev_classifier.py`) with ~20 canonical examples (Log4Shell → library_framework; MOVEit → file_transfer; specific Chrome CVE → browser not OS) as regression protection.
- **`other` bucket is still a non-trivial slice of the windowed catalog.** The classifier is deterministic, but unclassified entries mean either (a) the rule set is genuinely incomplete and needs additions, or (b) those entries don't fit the 14 designated layers and need a new layer. Either way, worth triaging the `other` bucket — I'd bet half of them could be re-bucketed with 5-10 added rules.

Net: this is unglamorous cleanup work and it's exactly the cleanup the repo needed. Ratio-estimation-with-manual-tweaks was always the weakest methodology in the project. Good commit.

### 1.4 Independent review (REVIEW-FINDINGS.md) — valuable external check, mostly acted on

Four personas (Hacker, Fresh Analyst, Data Freak, Curmudgeon) completed 10 total passes. This is a substantial amount of review work and the findings document is unusually concrete. Quick cross-check against what's been done vs. what's outstanding:

**Done since 2026-04-23:**

- Five text bugs fixed (`b190ce3`). Ransomware 191 → 186, Spring 59% → 64% heading, 2-4 → 2-6 NP+DI range, firmware 5 → 4, cross-page reduction range reconciled.
- 934 → 886 windowed KEV count fixed (`251535b`). Ratio-estimation error corrected.
- Glasswing extraction (`bf3f5a4`). Dashboard cleansed of speculative content; intelligence-assessment framing applied to `glasswing.html`.
- Auth-bypass DI widening (`d4d8f65`, `83af848`) — addresses the "widen as needed, disclose the widen" principle, though the disclosure part is still missing (§1.1 above).

**Open from REVIEW-FINDINGS.md punch list:**

- **"Reframe methodology as triage policy, not predictive model — use 'natural hygiene' not '30 days'."** Grep shows the HTML still has *"The filter is predictive, not retrospective"* (index.html line 914, periodicity.html line 438) and *"30-day patch cycle"* language throughout. **Copy not yet rewritten.** This is a framing change the author explicitly asked for; it should land.
- **"Forward-validate against new inbound (don't freeze CWE set yet — Mythos surge is validation opportunity)."** No forward-validation callout exists yet in the walkthrough. The Mythos section (§12) doesn't explicitly frame the Mythos surge as a validation opportunity for the filter. Recommend adding a paragraph to §12 or a new §7g.
- **"Compute values from data, don't hardcode (shared data.js architecture)."** Still two separate DATA blobs (dashboard and walkthrough); periodicity.html still has hardcoded chart arrays. The Data Freak recommendation is the right long-term architecture but represents significant refactoring work; I wouldn't rush it.
- **"Add changelog/errata to dashboard."** No changelog section exists. Given that the DI set is being versioned (§1.1) and the layer classifier was rebuilt (§1.3), a changelog is increasingly overdue. A `<details>` drawer at the bottom of dashboard.html listing date-tagged changes would suffice.
- **"Add sample sizes (n-counts) to rate charts."** Not yet done. One of the easiest wins — every bar chart showing exploitation rate should annotate the sample.
- **"Resolve cross-page denominator confusion (library 17.5% vs 0.05%)."** Still appears in both places. Needs a one-paragraph explainer: *"The library rate of 17.5% is the fraction of all library KEV entries that belong to known-NP components. The 0.05% number is the absolute exploitation rate across the OSV universe. Both are true; they answer different questions."*

**Other points I'd highlight from REVIEW-FINDINGS:**

- The Hacker persona's attack-path list is operationally useful and worth folding into the walkthrough's caveats or a new "Known limitations of the triage policy" subsection. *"Stored XSS → admin session theft (Tier 3, 30-day window, WAF-invisible)"* and *"Container escape via monthly OS gap (foothold + kernel CVE)"* are exactly the "here's what the filter won't catch" disclosures that make the analysis defensible.
- The Curmudgeon's framing push — *"the analysis is a conservative triage policy, not a predictive model"* — is the single most important framing change pending. This should land in the TL;DR, the §6 filter intro, and §14 caveats. Current text still leans predictive; the switch to triage-policy framing is a cleaner intellectual stance and disarms a lot of the circularity critique.
- Fresh Analyst's **survivorship bias point** (*"jackson-databind zero-exploitation may reflect attacker preference, not impossibility"*) is the single most underrated criticism in the document. The filter ignoring jackson-databind CVEs is treated as a win; the counter-argument is that attackers are ignoring jackson-databind because other classes are cheaper, and if the incentive shifts the filter's past performance won't hold. The walkthrough §14 caveats should explicitly name this. One paragraph.
- The Curmudgeon **"AI scan tier isn't reproducible"** objection is more serious than the response ("it has a documented query") concedes. "Have an AI look at it" and "have this specific model-temperature-prompt-version look at it" are different things. If the AI safety-net is going to be part of the triage policy, the prompt and model version should be pinned in the repo. Five-minute cleanup that materially improves defensibility.

### 1.5 Devil's-advocate on the last 30 hours of work

Playing sharp-pencil reviewer on the day's changes specifically:

1. **The auth-bypass widening's net effect was to recover numbers that looked worse after they dropped.** Spring was at 73% → dropped to 59% on pass 1 widening → rose to 64% after reclassification. Django was at 71% → dropped to 67% on widening. These numbers moving around over a 48-hour window without pre-registration is bad methodology hygiene. Forward-looking fix: from now forward, changes to the DI set should be announced-then-measured, not measured-then-announced. The changelog (§1.1) is the vehicle.
2. **Two KEV watch-list confirmations in one day is strong evidence, but N=2 and both from the same 4-day batch means the statistical weight is smaller than the optics suggest.** The watch list's true hit rate requires tracking false negatives (CVEs that made KEV without being on the watch list) and dwell-time-adjusted predictions. The refresh agent logs these but the dashboard doesn't display them. See §3.2.
3. **Glasswing extraction to a separate page is the right call on merit, but it slightly weakens the walkthrough's "why this matters" story.** The original structural argument — *"we're measuring how exploitation works, AI-assisted discovery is changing the denominator, here's why our filter matters in that context"* — is now split across two pages. The walkthrough's §12 (Mythos Detector) still exists but reads as context-adjacent rather than load-bearing. Consider whether §12 should either (a) be trimmed further since the Glasswing page now owns that content, or (b) retain a stronger "and this is why the filter matters now specifically" paragraph that uses the Mythos-discovery-rate context.
4. **Dashboard watch list data is stale re: the 2 KEV confirmations.** `docs/dashboard.html` lines 724, 731 still have `status:"watching", kevDate:null` for CVE-2026-33825 and CVE-2026-39987 respectively. The in-page JS cross-check on line 738 *does* auto-flip these to "confirmed" at page-render time (by matching against the live KEV catalog), so the rendered UI is correct. But the source data is inconsistent with what the daily report says, and the walkthrough (index.html) hand-edited those entries to CONFIRMED. Consequence: the dashboard's source-of-truth is the live KEV catalog via fetch; the walkthrough's source-of-truth is a hardcoded table. When the refresh agent updates one, it doesn't update the other. This is a case of the Data Freak's "shared data.js" recommendation becoming operationally needed, not just stylistically preferable.

### 1.6 What's robust

The core case has held up across five review passes and ten independent reviewer sub-passes. The things I want to explicitly flag as *not changing* under today's review:

- **NP+DI as a filter catches all 5 exploited CVEs in the 7-year Java backtest.** The three CWE-misclassification misses are a known, specifiable failure mode. That's a much stronger position than "the filter works" in the abstract.
- **The cross-ecosystem convergence is real** (three synthetic stacks + one real-enterprise manifest + one reactive Java stack all showing 60–90% reduction in rebuild-trigger dates). No reviewer has successfully pushed back on this.
- **The three-tier patching model is analytically clean** and the blast-radius framing (app-layer IF vs OS-layer HOW BAD) is the conceptual hook that makes the model transferable. Unchanged since pass 3.
- **The intellectual honesty on the 3 misses** (disclosure + root cause + proposed AI safety-net mitigation) is the single strongest credibility signal in the project and should not be watered down to preserve marketing headlines.

---

## 2. Walkthrough Restructuring — Remaining Items (Post-Pass-4)

The structural rewrite from passes 1-3 has largely landed; this section lists only what's still outstanding. In priority order:

### 2.1 Must-fix today (copy edits)

1. **Dashboard line 161 zero-miss headline.** Flagged in pass 4 §13.4 item 1 as *must-ship-today*. Still present. Fix per §1.2 above.
2. **Walkthrough TL;DR (line 177) zero-miss claim.** Replace with the 5-caught / 3-misclassified framing.
3. **Walkthrough §9 title and intro.** Retitle from "External Validation: The Zero-Miss Window" to "Cross-Validation Against Five Exploitation Databases." Update line 600 translation box.
4. **Walkthrough §10 line 686 zero-miss prescription.** Soften to "approach zero misses + track CWE disagreements."

### 2.2 High-value (30 minutes each)

5. **Add §6d: CWE Set Versioning & Changelog.** Per §1.1 above. Current DI set + version history + policy statement.
6. **Reframe as triage policy, not predictive model** (per REVIEW-FINDINGS punch list item 1). Grep for *"predictive"* in index.html and periodicity.html; replace with *"triage"* language where appropriate. Keep "predictive" where it actually refers to forward-looking watch-list predictions (that's a different meaning).
7. **Promote the 2/2 watch-list KEV confirmation** (§3 below). Pick the best single location (probably §13 Watch List) and add a callout with dates, CVEs, and days-on-watch.
8. **Survivorship-bias caveat** in §14. One paragraph on "zero-exploitation-for-some-classes may reflect attacker-preference rather than intrinsic non-exploitability." Disarms the Fresh Analyst's strongest critique.
9. **Cross-page denominator reconciliation** (library 17.5% vs 0.05%). One-paragraph explainer in both index.html and the dashboard's library section.

### 2.3 Medium-value (≥1 hour each)

10. **Add hacker-attack-path known-limits subsection.** Lift the 6 attack paths from REVIEW-FINDINGS and present as "known limitations of the triage policy." Builds defensibility.
11. **Pin the AI-safety-net prompt and model.** Currently the recommendation is "have an AI validate CWE assignments" without spec. Add `/scripts/cwe-validator.md` or similar with the exact prompt, model version, and temperature. Five-minute commit that turns a squishy recommendation into a reproducible pipeline.
12. **Sample-size (n-count) annotations** on all exploitation rate bar charts (REVIEW-FINDINGS punch list item 6). Every bar should say `(n=###)` adjacent.
13. **Forward-validation framing for Mythos.** Per REVIEW-FINDINGS note: "forward validation is twofold: validate against new inbound, and Mythos surge is unique validation opportunity." Add to §12 or new §7g.

### 2.4 Architecture (long-term)

14. **Shared data.js** (Data Freak pass). Significant refactor; not urgent. Would eliminate the DATA-blob drift risk but isn't blocking.
15. **Changelog/errata section on dashboard.** Becoming necessary given CWE-set versioning + layer-classifier rebuild + ongoing data updates. A `<details>` drawer with date-tagged entries.

### 2.5 What to keep as-is

Sections that shouldn't change despite the temptation:

- **§6c on OSV vs NVD denominators.** This is dense and some readers will skim it, but it's what makes the NP+DI thesis survive the "you're measuring what KEV selects for" critique. Resist trimming.
- **§7d real-enterprise backtest.** Strongest single section of the analysis. Don't cut or compress.
- **§14 Caveats.** Good as is. Just append the new caveats from §2.2 items 8 and 13.
- **§11 Reverse Proxy Myth.** Keep. It's a good dismissal of a specific counter-argument the author knows the analysis will face.

---

## 3. Watch-List 2/2 KEV Confirmation: The Under-Promoted Headline

This is the single most actionable new piece of evidence in the repo and it's currently documented only in:
- `kev-tracking.json` (`kev_additions.watch_list_kev_promotions_this_run`)
- `analyst-reports/2026-04-21.md` / rolling.md mentions the two CVEs existed on the watch list
- `docs/index.html` §13 table rows (updated to CONFIRMED status)
- `docs/dashboard.html` WATCH_LIST object (still stale as noted above)

What's missing: **a clean prospective-accuracy metric callout anywhere on the site.** The watch list is the closest thing the project has to a pre-registered forward-looking test — the analyst flagged these CVEs on 2026-04-18 and 2026-04-19, 4 days before CISA confirmed them. That's the exact scenario pass 2 §8.2 asked for: *"pre-register a forward-looking test now."* The watch list has been that test all along; it's just not being marketed as such.

### 3.1 Recommended callout

**Location:** dashboard hero section (above the NP+DI filter section) and walkthrough §13 opener.

**Text (suggested):**

> **Watch-list prospective accuracy (April 2026): 2/2 confirmations within 4 days.** CVE-2026-33825 (Windows Defender "BlueHammer") was added to the watch list on 2026-04-18 with `weaponized` maturity; CISA added it to KEV on 2026-04-22 (4 days). CVE-2026-39987 (Marimo pre-auth RCE) was added on 2026-04-19 after Sysdig telemetry documented 662 exploit events; CISA added it to KEV on 2026-04-23 (4 days). The watch list has now correctly predicted both of its April-grade KEV candidates. This is the project's first prospective validation checkpoint — the list predicted the CISA decision on these two CVEs, not retrospectively explained it.

### 3.2 Caveats to state alongside

Don't overclaim this. Specifically:

- **N=2 is small.** This isn't statistical validation; it's consistency with prior expectation. We need several months of tracking to distinguish skill from luck.
- **False negatives aren't being tracked visibly.** If CVE-X makes KEV without being on the watch list, that's a miss. The refresh agent does track these (kev_tracking.json has `"new_since_prior_run"` data) but the dashboard doesn't display a "list miss rate" or "KEV adds not on our list." Recommended: add a small card on the dashboard showing `watch_list_hits / total_april_kev_additions` (currently ~2/24, but many of the 24 are pre-2026 CVEs added for housekeeping — the meaningful denominator is "2026-era KEV adds we could have predicted in advance").
- **The pre-watchlist exploitation telemetry was already public.** Both CVEs had Sysdig/Horizon3/public-PoC signal before being added to the watch list. The list didn't uniquely discover these — it correctly synthesized existing exploitation evidence into "this will hit KEV." That's still useful but it's a weaker claim than "we predicted exploitation before it was visible."

### 3.3 Dashboard card proposal

Small KPI card, 1/4 width:

```
+-----------------------------+
|  WATCH LIST PROSPECTIVE     |
|  2/2 confirmed Apr 2026     |
|  Avg lead time: 4 days      |
|  See Section 13 for details |
+-----------------------------+
```

Also commit to updating this monthly with new denominators. The metric is only meaningful if it's tracked over time, not sampled.

---

## 4. Dashboard and Cross-Page Updates

Condensed from pass 4 and extended with today's items.

### 4.1 Dashboard

- **[Urgent]** Fix zero-miss headline (§1.2).
- **[Urgent]** Reconcile watch list JSON source data for CVE-2026-33825 and -39987 (flip `status: "watching"` to `"confirmed"` and add `kevDate`). The live cross-check JS masks this but the source inconsistency will bite.
- **[High]** Add 2/2 watch-list confirmation KPI card (§3.3).
- **[High]** Add changelog/errata `<details>` drawer at page foot (REVIEW-FINDINGS punch list item 4).
- **[Med]** n-count annotations on rate bars (punch list item 6).
- **[Low]** Move Finance Sector and Why-Most-Don't-Get-Exploited to collapsed expandables (pass 3 §3.4 recommendation, still outstanding).

### 4.2 Five-page architecture (walkthrough, dashboard, periodicity, cve-reference, glasswing)

The page count grew from 4 to 5 with glasswing.html. The nav bar was updated consistently on all five pages — that's cleanly done. Two lingering issues:

- **Glasswing page is under-integrated from periodicity.html.** The Glasswing angle is arguably the strongest "why this matters now" hook for the periodicity analysis (AI-assisted discovery is expanding the library-CVE volume, the filter helps you cope). But periodicity.html doesn't link to glasswing.html and doesn't mention the Mythos context. A one-sentence link-out at the end of the periodicity intro would fix this.
- **evergreen.html and osv-exploitation.html are still in limbo.** Not linked from any other page, not marked as scratch. Pass 4 §13.2 flagged this. Either promote to linked or mark as scratch; the current "unlinked but indexable" state is the worst of both worlds.

### 4.3 Navigation heuristic

Current nav: `Walkthrough - Dashboard - Periodicity - CVE Reference - Glasswing` — five pills, current-page highlighted. That's fine. The only nit I'd raise is that `Periodicity Analysis` as a nav label is less readable than `Backtest` or `Filter Evidence` would be. Not urgent.

---

## 5. Daily Scan — 2026-04-24

Refresh agent last_run = `2026-04-24T03:00:00Z`. Commit SHA tracked as `3191334`. Cross-checked against kev-tracking.json, live CISA KEV, NVD API, and today's commits.

### 5.1 KEV adds (24h)

**Two watch-list confirmations** covered in §3. April KEV total now **24** (up from 22 yesterday), exactly at the Q1 2026 monthly average. Catalog version 2026.04.23.

- **CVE-2026-33825** Windows Defender "BlueHammer" LPE. Microsoft is a Glasswing participant. Added to KEV 2026-04-22, 4 days after watch-list flag. Watch-list rationale held: pre-patch PoC leak Apr 3 + ITW activity Apr 10 + Apr 16 additional activity. Browser-delivered exploit-chain component. Now 19 days from disclosure to KEV — on the slow end but within the 46-day window established by the Cisco SD-WAN example.
- **CVE-2026-39987** Marimo pre-auth RCE. Added to KEV 2026-04-23, 4 days after watch-list flag. Watch-list rationale held: Sysdig 662 exploit events + NKAbuse variant + pre-auth WebSocket RCE attack surface. Marimo is an AI-notebook product — continues the "AI-tooling-products-are-the-current-exploitation-body-count" pattern from 2026-04-19.

Neither is a Glasswing-attributed / Mythos-credited CVE. Both are conventional researcher-disclosure -> attacker-weaponization -> CISA-listing paths. Glasswing attributions remain at 3 Claude-in-credit-line CVEs, 0 in KEV.

### 5.2 NVD MTD / volume

- April MTD = **4,772** (day 24), extrapolates to **5,965** full-month.
- Fully-populated-day average (Apr 20-22): ~293/day. Day 24 same-day count 23 and growing.
- 2026 prior months: Jan 5143, Feb 4808, Mar 6304.
- April running 5.5% below March and on-track for the conservative Glasswing-inflation projection, not the aggressive one.
- Counter-argument the refresh agent correctly notes: NVD publishing lag is 2-8 weeks, so Glasswing-disclosed CVEs may not yet be visible in April. Mid-to-late May is when a Mythos-attributable inflection would first be measurable.
- **Volume does not yet corroborate the AI-scan-inflation hypothesis.** That's consistent with both "it's happening but invisible due to lag" and "it isn't happening at the scale projected." Can't distinguish for another 3-6 weeks.

### 5.3 Glasswing / Mythos

- Total Mythos-linked fixes: **283** (unchanged). Firefox 150 (271 fixes, 41 CVE-tier, 3 Claude-credited) still dominates the number.
- **6 credited CVEs today** — up from 3 yesterday (CVE-2026-4747 FreeBSD NFS, CVE-2026-5194 wolfSSL, CVE-2026-5588 Bouncy Castle, CVE-2026-6746 / -6757 / -6758 Firefox). None in KEV. The Firefox Mythos trio (MFSA 2026-30) is the largest single-advisory Claude-credited batch to date.
- No new direct-attribution CVEs in the 24h window.

### 5.4 Participant-self-scan candidates

Per kev-tracking.json, still open candidates for the `probable_participant_cves` table:

- **CVE-2026-40050** CrowdStrike LogScale (9.8, CWE-22 + CWE-306). Flagged in pass 3 as strongest candidate. Still pending credit-line verification.
- **CVE-2026-20093 / 20160** Cisco IMC / Smart Software Manager On-Prem (both 9.8). Pending verification.
- **CVE-2026-24164** NVIDIA BioNeMo (CWE-502). Deserialization, non-strict-NP-DI — hold as watch.
- **CVE-2026-1386** AWS Firecracker jailer. Local vector — disqualifies for NP+DI.
- **CVE-2026-39861** Anthropic Claude Code sandbox. Local vector — disqualifies for NP+DI but participant-self-scan-interesting since Anthropic is the principal.

**No changes to config.json's `probable_participant_cves` this run** — all above need credit-line verification before admission.

### 5.5 Counter-argument / discipline check

Three honest checks I want to keep in the record:

1. **Three straight days of the CVE firehose running at or below March pace.** The aggressive Mythos-inflation projection (~9000/month by summer) increasingly looks wrong or extremely delayed. The analysis should note this — current framing is implicitly preparing for a volume surge that isn't appearing.
2. **2/2 watch-list KEV confirmations is also a survivorship-biased datapoint.** We only talk about the watch list when it has hits. If CVE-X hits KEV tomorrow and it wasn't on the watch list, we should track and report that just as visibly.
3. **The 4-day watch-list-to-KEV lead time is within the 2-6 week Cisco-SD-WAN envelope but at the lower end.** That either means the watch-list criteria are well-calibrated (good) or it means the two confirmations happened because both CVEs had unusually clean exploitation-evidence profiles (telemetry, PoCs, press coverage). The next confirmation coming from a CVE with less public evidence would be the real test of list skill vs. list luck.

### 5.6 Thesis-challenge counter-examples

Still empty. CVE-2026-33827 (Windows TCP/IP RCE) — now 9 days post-disclosure, still not in KEV — remains the closest outstanding contender but remains product-level, not library-level.

### 5.7 Net daily finding

**Nothing today contradicts the periodicity review above.** The 2/2 watch-list confirmation strengthens the prospective-prediction case. The flat volume numbers continue to push against the aggressive Mythos-inflation story. The absence of Glasswing-attributed CVEs in KEV remains consistent with either "it takes time" or "the threat model overestimates AI-discovery exploitation velocity" — no new evidence to distinguish.

No config.json changes this run. Watch-list and probable-participant tables unchanged (pending credit-line verifications).

---

## 6. Consolidated Punch-List (Post-Pass-5)

Carrying forward from pass 4 §13.4 and adding today's items. In priority order:

**Ship today (copy edits, 15 min or less each):**

1. **[5 min]** Dashboard line 161: zero-miss headline fix.
2. **[5 min]** Walkthrough line 177 TL;DR: zero-miss fix.
3. **[10 min]** Walkthrough §9 title + line 600 translation box + line 686 prescription.
4. **[5 min]** Dashboard WATCH_LIST source data flip for CVE-2026-33825 and -39987 (`status` and `kevDate`).

**Ship this week (1 hour or less each):**

5. **[30 min]** Walkthrough §6d CWE Set Versioning & Changelog (per §1.1).
6. **[30 min]** 2/2 watch-list KPI card on dashboard + callout in walkthrough §13 (per §3).
7. **[30 min]** Reframe "predictive" to "triage policy" across index.html and periodicity.html (REVIEW-FINDINGS punch list item 1).
8. **[20 min]** Survivorship-bias caveat paragraph in §14.
9. **[20 min]** Cross-page denominator reconciliation (17.5% vs 0.05%).
10. **[15 min]** Pin AI-safety-net prompt/model in `/scripts/cwe-validator.md`.
11. **[30 min]** Sample-size (n-count) annotations on all rate charts.

**Ship this month (2 hours or more each):**

12. **[2-3 hrs]** Changelog/errata `<details>` drawer on dashboard (covering: DI CWE-set versions, layer-classifier rebuild, text-bug fixes, scheduled-data refresh).
13. **[3-4 hrs]** Hacker-attack-paths known-limits subsection in walkthrough.
14. **[1-2 hrs]** Evergreen/OSV-exploitation page promote-or-mark-scratch decision.
15. **[6-8 hrs]** Shared `data.js` architecture (Data Freak punch list item 3).

**Forward-validation (ongoing):**

16. Monthly update of watch-list prospective-accuracy card with hits, misses, false-negatives.
17. Monthly re-run of the 7-year Java backtest to confirm the AI-safety-net pass still catches new CWE-misclassifications before they accumulate to KEV.
18. Mythos surge watch continues — currently null inflation through late April; reassess mid-May.

---

## 7. Overall Read

The project is in the best shape it's been in since I started reviewing. The independent-review pass was the right move — it surfaced structural critiques that would have been painful if they'd come from outside readers, and most were addressed within 24 hours. The DI widening was the hardest call of the week and I think the author got it right on merit but failed on disclosure — the CWE-set versioning changelog is the highest-leverage 30-minute edit left in the repo. The zero-miss overclaim is embarrassing given that pass 4 flagged it and the better story (5 caught + 3 misclassified + safety-net mitigation) is just waiting to replace it.

The 2/2 watch-list KEV confirmation is genuinely exciting. It's the first prospective-prediction win the project has logged. Don't sit on it.

The thing I'd most recommend before the analysis gets read outside the team: **reframe the entire paper's thesis from "predictive model" to "minimum-action triage policy."** That framing survives every reviewer critique I've seen across five passes. "Predictive model" doesn't, and you'd have to defend something the filter isn't and doesn't claim to be. The triage-policy framing is the author's own stated intent per REVIEW-FINDINGS — land it in the copy.

One genuine devil's-advocate caveat I owe the record: I'm still the internal analyst reviewer, running against my own recommendations from five previous passes. There's a non-trivial risk that I'm missing critiques a fresh external reader would surface because I've been inside the argument too long. Before this hits any external audience, a one-shot review from someone who hasn't read the project before would be worth 10 hours of my time.

---

*End of review (fifth-pass complete, 2026-04-24).*
