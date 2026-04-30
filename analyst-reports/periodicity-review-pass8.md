# Analyst Review — Eighth Pass (2026-04-30)

**Author:** kev-analyst (scheduled run)
**HEAD at review:** `7fd9609` (today's refresh tracking commit; analytic HEAD `70553e8` Refresh: KEV 1585, NVD Apr 5720 MTD, Spring AI cluster on watch list)
**Predecessor pass:** `301950e` periodicity-review.md from 2026-04-29 (which itself superseded passes 5–7). This is the tenth analyst-side review.
**Scope:** brief in `analyst-reports/periodicity-review-brief.md` plus the four pages it names (`docs/periodicity.html`, `docs/index.html`, `docs/dashboard.html`, `docs/cve-reference.html`). Bonus: the new FOSS sub-7 scratch page (`docs/foss-sub7.html`), the rebuilt Mythos page (`docs/glasswing.html`), and the live model-run-log (`data/model-run-log.json`) wired in 2026-04-29.

---

## 0. Headline (read this if you read nothing else)

**Yesterday's review backlog substantially closed in the last 24 hours, and a new piece of analysis (FOSS sub-7) plus a wired-up Mythos model-run-log feed are live.** The single longest-running unfixed item in the review tree — the dashboard line-166 "zero misses" framing, flagged in pass 5 (2026-04-24) and unaddressed for six days — is now resolved. So is the OS-layer 21/76% leak on the periodicity page, the EPSS hero `n=6` caveat, the watch-list KPI band on the dashboard, the Spring AI 5-CVE cluster being added to the watch list, and the §4a hero-KPI "absorbed by supplements" labeling. That's six items from the analyst backlog (commit `dc4af0d` "Critical fixes" + `d8bfafb` "Analyst backlog #8 + #9") landed in one morning. This is the largest day-over-day reduction in the review backlog the project has had since the 2026-04-23 reconciliation pass.

What's *new* substantively (commits since yesterday's `301950e`):

1. **FOSS sub-7 scratch page** (`b40630d` + `31f42fa` + `fe5eac0`). 135 distinct medium-severity FOSS server-side library CVEs with exploitation evidence, scored against NP+DI+DQ + Hacker. Headline catch rates: NP+DI raw 82.2% (111/135), NP+DI+DQ 85.9%, Hacker S+A 25.9%, union 87.4%. Explicit honest counter-callout: 134 of 135 records are NP-classified, so on this dataset NP+DI essentially collapses to "is it injection." Includes a new TTE comparison: 136d median for mediums vs 11–34d for recent C/H KEV — but the 3 KEV-confirmed sub-7 entries themselves have a 25d median, comparable to C/H. Honest read on both sides.
2. **Mythos page rebuilt** (`902ec71` light theme + standard nav, `af4ffbb` `data/model-run-log.json` wired into §1). The "Today's Model Run" table is now a live feed embedded from a canonical, schema-versioned JSON file. Bootstrap run includes 5 in-scope events for 2026-04-29.
3. **Spring AI 5-CVE cluster added to watch list** (`dc4af0d` #5 + `7fd9609` refresh). First time the auto-monitoring loop's `np_di_candidates` output actually fed a live prospective prediction. -40967 (FilterExpressionConverter injection) and -40978 (CosmosDBVectorStore SQLi via doDelete) have detailed entries; -40966/-40979/-40980 are companion CVEs awaiting individual classification.
4. **build-mechanics §3 fleshed out** (`b4113a8`) with platform-BOM and DIY paths for "get-latest" workflows.

What's still open from yesterday:

1. **Walkthrough §10 (Reverse Proxy Myth)** still standalone, still redundant with §9a Operational Model `#wafs` (yesterday's #4, pass 7 §6 #16). Demote-or-merge call still owed.
2. **Walkthrough §4f duplication** — the strategy-efficiency table and 13-library NP+DI table still live on both `index.html` §4f and `periodicity.html` §7 (yesterday's #4, pass 7 §6 #16). One canonical home; the other shows summary + deep link.
3. **Mythos breach disclosure** to walkthrough §12 — still missing. Pass 7 §6 #6 recommended a one-sentence addition. Anthropic Mythos Preview breach (2026-04-21/22) is now a major news cycle. Two of today's three Mythos news hits (TheHackerNews, arnav.au, The National UAE) cover it as part of the broader "Mythos finds thousands of zero-days" story. Defensible to add a sentence; defensible to skip; explicit decision needed instead of carry-forward inertia.
4. **CWE-set version badge / changelog** (pass 7 §6 #4 + #8) — still not visible on any page. The `data/di-cwe-backtest.json` per-CWE empirical exploitation backtest is the strongest defensive evidence the project has against the goalpost-moving criticism, and it's still buried.
5. **Walkthrough §9 quick-checklist** "track your filter's hit rate over 6 months — should produce zero misses" — yesterday's review noted it. Today it reads as edited (commit `dc4af0d` #3); see §1.4 below for verification.
6. **CVE-2026-0234 (Palo Alto Cortex XSOAR)** — pass 6/7 carry-forward as probable-participant candidate. *Today's `kev-tracking.json` `np_di_candidates` no longer flags it* — the refresh agent has moved on to ConnectWise + Spring AI. The candidate has been silently dropped after three carry-forward passes. That's an implicit decision-to-skip; prefer to make it explicit with a one-line note in the rolling report ("CVE-2026-0234 closed without action: third-party researcher signal emerged 2026-04-26 / vendor pulled disclosure / scope-call: not HTTP-parsing-adjacent") rather than carry-forward inertia.

Today's net leverage opportunity: the FOSS sub-7 finding is genuinely interesting and deserves a 1-section integration into the walkthrough, not just a scratch page. Section §3a or new §3f: "the structure test is essentially invariant down to mediums for already-exploited bugs — but its discrimination changes." This is the right pressure-test framing; details below in §1.7.

---

## 1. Assessment of the Periodicity Analysis (current HEAD)

### 1.1 Is the NP+DI methodology sound?

**Strong on C/H, much weaker on mediums in this new dataset, with a useful sensitivity test now in the repo.** The pass-7 §1.1 / yesterday §1.1 assessment of the NP+DI rule against C/H is unchanged: empirically validated against `data/di-cwe-backtest.json`, package-role-aware NP correctly excludes commons-text-as-utility, the auth-bypass widening is half-supported empirically. None of those moved.

The new wrinkle is `data/foss-sub7-scoring.json`. Down at CVSS<7:

- **134 of 135 packages classify NP.** That's because the source filter (`scripts/foss_sub7_server_side_filter.py`) selected for server-side libraries by package metadata, which is essentially a proxy for "in the trust-boundary cluster." So at this severity the manifest itself is the discriminator, not NP-vs-non-NP.
- **DI catches 112 of 135 (83.0%)** — almost the same as NP-and-DI (111). DI is doing essentially all the work; NP is approximately constant.
- **The CWE distribution skews different from the C/H-canon.** 67 of 135 are XSS (CWE-79), 19 path-traversal, 6 CSRF, 4 SQLi. At C/H the DI distribution is dominated by injection and traversal; here it's dominated by XSS (a CWE that has a 1.19% empirical exploitation rate per `data/di-cwe-backtest.json` and is sometimes argued out of DI). That skew is a real signal that the medium-severity bugs that get exploited *look different* from C/H.
- **Hacker S+A's catch rate falls to 25.9%** (35/135). At C/H the union is 91% on the canonical 7-year backtest. At medium it's 87% — but the union is now mostly NP+DI+DQ (which is mostly DI-alone) because the hacker discriminator is properly conservative on the smaller-blast-radius bugs. **0 of 4 KEV-confirmed sub-7 entries cleared S+A.** That's the cleanest piece of evidence the hacker rubric is doing what it's supposed to (reserving S/A for actually scary stuff, not commodity XSS).

The page reports both halves of this honestly via paired success/warning callouts. Good. What's still owed is folding the sensitivity-of-the-discriminator finding into the walkthrough — see §1.7.

### 1.2 Is the cross-framework validation convincing?

**Yes for the C/H 7-year canonical 58-pkg manifest, with the same caveats as yesterday.** No new substance here in the last 24h; the canonical-manifest reconciliation from 2026-04-28 is the document of record and `tests/test_seven_year_npdi.py` is the regression test. The pass-7 recommendation to add a 5th synthetic manifest from a less-canonical ecosystem (Rails, Go, Phoenix) is still worth doing eventually but is not urgent.

The FOSS sub-7 dataset is a *severity* sensitivity test rather than an ecosystem one. The two pressure tests run in opposite directions: cross-framework asks "does the filter work in non-Java ecosystems at C/H?" (answer: yes, with 14-14-14 convergence and one 7-year per-framework backtest at 30%); cross-severity asks "does the filter work below C/H?" (answer: 87% catch but with the discriminator collapsed). Both belong on the same evidence ladder.

### 1.3 Is the OS chaining / kill-chain framing correct?

**Now closed.** Yesterday's #2 fix (commit `dc4af0d` #2) replaces the 21/76% inflated headline on the periodicity OS-Layer cadence-comparison table with the cleaned 10–12 / ~70% number, leading the section with the cleanup explanation rather than burying it in a footnote. The dashboard "Three Response Lanes" card already led with "60–70% on the noise-cleaned LPE set" as of yesterday. Both surfaces now match the walkthrough §7's framing. Pass-7 §1.3 had this as a partial-close item; today it's complete.

The remaining pass-7 carry-forward — the in-container-privesc vs container-breakout distinction (pass 7 §6 #11) and the systemd 12-of-21 LOCAL-CWE keyword inflation breakdown (#12) — are unchanged. These are honesty-deepening items rather than headline corrections; defer.

### 1.4 Does the EPSS / external-validation analysis hold up?

**Pass 7 hero-KPI caveat now in.** Commit `d8bfafb` #9 adds the explicit `n=6 with EPSS coverage` qualification to the §15 EPSS hero callout, separating Ghostcat 2020 / Tomcat CGI 2019 (pre-EPSS-public, can't have been flagged at any threshold) from the 6 events EPSS could plausibly have caught. Closes the fair-but-loaded reading of the 34.7-day-faster claim. Strongest single piece of analytic content remains the §15 EPSS rebuild from 2026-04-26.

Outstanding pass-7 recommendation to add a 1-paragraph summary callout at the top of §15 (now 7 cards long) is unchanged.

### 1.5 Devil's-advocate: what could undermine the conclusions?

User preferences ask me to push the other side. Today's incremental adversarial points (pass 7 §1.5 covered the five strongest hostile angles in detail; not repeating those):

1. **The FOSS sub-7 dataset has a selection-bias problem the page is honest about but doesn't fully disclose.** The 135 records were filtered down from OSV per-ecosystem feeds by (a) CVSS<7, (b) server-side library by package metadata, (c) exploitation evidence in KEV/MSF/EDB. That's "exploited mediums in NP-classified server-side libraries." The catch-rate is computed against that population — not against "mediums in general," nor "exploited mediums in any package." A hostile reviewer can fairly say: the filter that built the dataset selected for the kind of bug NP+DI is best at catching, and then the page tested NP+DI on it. The defensible response: that's exactly what the page acknowledges in the second callout ("the discriminator is doing weaker work than at C/H… mediums-in-NP-packages-with-injection-CWEs is the population the model is built around"). But **the page doesn't compute the analogous control rate** — what fraction of *unexploited* mediums in NP-classified packages would also clear NP+DI? If that number is 70%+ the FPR is poor; if it's 20% the filter is meaningfully discriminating. Without that control number the 87% is a one-sided result. That's a 30-minute analysis to add and would close the loop.
2. **The Mythos page §1 "Today's Model Run" is bootstrap-only.** As of today the runs[] array has exactly one entry (2026-04-29 bootstrap). The model-run-log architecture is correct; the prospective-precision-recall promise in the §1 explanation ("after ~30 days of runs, prospective precision/recall by tier becomes statistically meaningful") is a 30-day-from-now claim. Today the page is showing yesterday's analyst-curated event list, not a multi-day prospective record. A reviewer who lands on the page expecting a live feed will see "1 run, 5 events, all bootstrap" and need to wait for the agent loop to fill it in. **Recommend adding a `runs.length` < 5 banner** that says "Run log is bootstrapping — 1 of ≥30 runs needed for prospective precision/recall scoring" so the gap between architectural promise and current state is on-page.
3. **The model-run-log says "NVIDIA BioNeMo CVE-2026-24164 — flagged as probable participant self-scan" but it's NOT in `config.json` `probable_participant_cves`.** Two pages are now inconsistent. The criterion conflict is: BioNeMo is research/ML (not strict HTTP-parsing-adjacent), but the bug class (CWE-502 deser) and the participant-vendor + no-known-third-party-credit signals fit. Either widen the qualification rule (and note the widening on the Mythos page so a reviewer doesn't catch the inconsistency), or downgrade the run-log framing from "flagged as probable participant self-scan" to "candidate — pending Mythos panel review." Today's report recommends the latter (more conservative); see §3.3 below.
4. **The "five in-scope events" Mythos count for 2026-04-29 includes one 2024-vintage CVE (ConnectWise CVE-2024-1708).** The model-run-log has it correctly classified (KEV-newly-promoted) and `nvd_published: 2024-02-21` is honest. But the run is intended to score the model on *new inbound*, and a 2-year-old CVE that just got promoted to KEV isn't new inbound — it's KEV-catalog-curation-noise. **Recommend a `kev_promotion_only: true` flag** on the event schema so the run-log can correctly distinguish "new disclosure scored fresh" from "pre-existing CVE newly promoted to KEV." Otherwise the in-scope counts will be artificially inflated by KEV catalog churn.
5. **The watch-list KPI band's "5/19 promoted" hit-rate has a denominator-inflation problem.** Five of 19 watch list entries promoted to KEV is the headline, but two of those 19 are the new Spring AI cluster entries added today (within the last 24 hours). Those are not "predictions that have had a chance to fail" yet — they're predictions that have had ~12 hours of exposure. A more honest scope is "5 of 14 with at least 7 days exposure" or "5 of 12 active for ≥21 days." This isn't a reason to drop the headline; it's a reason to add an exposure-weighted variant, especially as new entries get added prospectively going forward.

### 1.6 What's new since yesterday's review (`301950e`)

Commits since yesterday's review HEAD, ordered by analytic substance:

| Commit | What | My take |
|---|---|---|
| `dc4af0d` | Six-item analyst-backlog cleanup pass | Largest leverage commit of the cycle. Closes 5 items pass 5/6/7 had been carrying. |
| `d8bfafb` | Watch-list KPI band on dashboard + EPSS n=6 caveat | Two more backlog items closed; KPI band is the single best forward-validation surface in the project. |
| `31f42fa` + `b40630d` + `fe5eac0` | FOSS sub-7 model backtest pipeline + scratch page + TTE | Genuinely new analytic substance. Honest both-sides framing. Ready to fold into walkthrough as sensitivity test. |
| `af4ffbb` + `902ec71` | Mythos page rebuild + model-run-log wired | Right architecture; bootstrap-only today, prospective value compounds with daily runs. |
| `b4113a8` | Operational Model §3 platform-BOM + DIY paths | Polish. Reads cleanly. |
| `70553e8` + `7fd9609` | Today's refresh — KEV 1585 unchanged, NVD Apr MTD 5,720 (extrap 5,920), Spring AI on watch list | KEV unchanged from yesterday (CISA hasn't published 04-29/04-30 entries yet). NVD pace ~140/day for last 24h, slower than running average. |

Net read: yesterday's review was approximately a bookkeeping note ("here are 4 things still flagged"); today's review is a status note ("most of yesterday's items closed; here are the new ones"). The project is in a tightening cycle, not a restructuring cycle.

### 1.7 The FOSS sub-7 finding deserves walkthrough integration, not just a scratch page

The scratch banner on `foss-sub7.html` reads "not linked from nav · for ad-hoc data exploration · generated 2026-04-29." That's the right state for an experiment whose conclusions aren't yet load-bearing. But the substantive finding is load-bearing: **NP+DI's discrimination is severity-dependent.** At C/H the NP-vs-non-NP split is roughly 55/45 in the 7-year canonical manifest; at this medium dataset it's 99/1. That's a real change in what NP is actually doing, and the walkthrough's §3a NP+DI section should disclose it.

Recommended walkthrough §3a addition (~3 sentences, end of §3a): "The structure filter's *discrimination* changes with severity. At C/H, NP-vs-non-NP is roughly 55/45 — the filter is doing real work telling them apart. At medium severity, ~99% of *exploited* server-side library CVEs are in NP-classified packages already (foss-sub7 sensitivity dataset, n=135), so NP loses discriminating power and DI is doing the work alone. The hacker S+A test responds correctly: 25.9% catch at medium vs ~67% at C/H, and 0/4 KEV-confirmed sub-7 entries clear S+A. The filter is invariant across severities for the *kinds of bugs that get exploited*; what changes is the marginal value of each axis." Link to `foss-sub7.html` for the data.

This is also a useful answer to a hostile reviewer's question "doesn't NP+DI just collapse to 'has an injection CWE' once you go below C/H?" — the answer is "yes, that's why the hacker rubric is the discriminating tool below C/H, and we measured it."

---

## 2. Walkthrough Restructuring Recommendations

The brief's mental model — "the walkthrough is still the original observational analysis; recommend a section outline" — is now wrong against today's HEAD by ~9 days and ~95 commits. Yesterday's review made the same point. Today's incremental list:

### 2.1 Current section structure (unchanged from yesterday — already converged)

```
1.  The Problem
2.  The First Clue: Where Exploits Actually Land
2a-c.  Stack Layer Rates / Network-Parser Signal / Libraries Deep Dive
3.  The Threat-Based Prioritization Model: Two Independent Operationalizations
3a-e.  NP+DI / DI CWE Set / Falsifiability / Hacker / Churn cost
4.  Does It Actually Work? Cross-Framework Validation
4a-f.  14-14-14 / Strategy comparison / Silence windows / Catches / Django weak / Real Java manifest
5.  Why Most Criticals Don't Get Exploited
6.  Time-to-Exploit Compression
7.  Land & Expand
8.  External Validation
9.  Operational Response by Estate Maturity (Cat 1/2/3)
10. The Reverse Proxy Myth
11. Exploit Watch List + Thesis Challenge
12. Caveats
```

Don't restructure. Don't move sections. The §4 sidebar surfacing committed 2026-04-29 is the right shape for the heaviest section.

### 2.2 What to keep, cut, move (delta vs. yesterday)

**Keep as-is:** §1, §2, §3 (with new sensitivity addition §1.7 above), §4 (with the canonical-manifest reconciliation note from yesterday §2.2), §6, §7 (now cleaned), §8 (EPSS hero now caveated), §9 (reworded), §11. All converged.

**New tighten item (today):**

- **§3a sensitivity addition.** ~3 sentences on the FOSS sub-7 finding. Link to scratch page. See §1.7.
- **§3a or §3b CWE-set changelog box.** The pass-7 recommendation (still open). One row noting CWE-444 added 2026-04-22 (Netty miss → 8.8% empirical rate), CWE-434 removed 2026-04-?? (Tomcat-PUT misclassification), the auth-bypass widening 2026-04-23 (CWE-287/289/306/345/693/863/1321 — half-supported empirically), and the 2026-04-28 canonical-manifest reconciliation (175→194 events, 34→40 NP+DI). Disclosure-with-rationale closes the goalpost-moving criticism cheaply.
- **§12 Mythos breach disclosure.** One sentence. Pass 7 §6 #6 carry-forward. Either add "Anthropic disclosed a Mythos Preview access breach in late April 2026; leaked-access actors can scan for bugs while defenders cannot — this asymmetry is the operational concern" or make an explicit decision to skip (with rationale: out of scope, not yet CVE-attributable, etc).

**Carry-forward unchanged from yesterday §2.2:**

- §4f duplication with periodicity §7. One canonical home.
- §5 reframe as "what the filter correctly excludes."
- §6 reframe as supporting §3e ("hidden cost of not filtering").
- §8a WAF defensibility — promote to top-level §8 successor or merge with §9a.
- §10 (Reverse Proxy Myth) — demote to callout in §9a or move to Operational Model entirely. **Yesterday's #4. Pass 7 §6 #16. Pass 6 §2.2.** This has been the second-longest-running unfixed item after the dashboard zero-miss (now closed). Ready to action.

### 2.3 Where the periodicity / FOSS sub-7 / Mythos findings fit (already integrated, with one gap)

- §3 introduces the model. **§3a needs the severity-sensitivity sentence** (§1.7).
- §4 says "and here are the cross-framework results."
- §8 says "and here's how it compares to existing exploitation signals."
- §9 says "and here's how to operationalize it given your estate's maturity."
- **§11 (or new sub-section) could surface the live model-run-log link.** Currently the model-run-log is on the Mythos page; the walkthrough's §11 has the watch-list table but doesn't reference the parallel feed. A 1-line "Today's prospective scoring of new inbound CVEs lives on the [Mythos page](glasswing.html#model-run)" would tie the architecture together.

### 2.4 The "zero-miss" framing — closed

**Yesterday's #1 is closed.** Dashboard line 166 (now line 165 post-edit) reads:

> "Across Spring Boot, Node.js/Express, and Django/Python stacks over 12 months, this reduces rebuild-trigger dates by 64–86%. The 12-month sample has only one in-scope exploited CVE (every strategy catches it), so it scores workload not discrimination. Discrimination is scored on the 7-year canonical 58-package manifest: 10 of 11 actually-exploited events caught directly (NP+DI+DQ ∪ Hacker S+A); the 1 remaining is absorbed by floor-sweep + threat-intel supplements."

That's the right frame. Walkthrough §4b honest disclosure, §9 quick-checklist reword, §12 caveats reword all in (commit `dc4af0d` #3, #4). §4a hero KPI label updated (commit `dc4af0d` #6) to "caught directly on 7-year backtest / 1/11 absorbed by supplements." Periodicity §7 conclusion at line 839 still says "12-month synthetic stacks have zero misses" but it's now correctly scoped to the 12-month-window claim, paired with the §665 honest framing about 113 non-trigger CVEs, and not contradicting the 7-year story. Acceptable.

### 2.5 Periodicity page should remain separate

Confirmed against today's HEAD. The architecture (walkthrough = argument, periodicity = evidence, cve-reference = audit trail, dashboard = live data, build-mechanics = how-to, glasswing/Mythos = intel + prospective feed, foss-sub7 = scratch sensitivity test, evergreen = scratch evergreening test) is the right shape. Don't touch.

---

## 3. Dashboard Updates

### 3.1 What's now in (yesterday's #1, #2, #8, #9 closed)

1. **Line 165 banner** — scoped/replaced. ✅
2. **Watch-list KPI band** under the Watch List section header — added (`d8bfafb`). 4 tiles: 5/19 promoted, 14 active, ~4d lead time over KEV, 0 false positives. ✅ This is the single cleanest piece of forward-validation evidence in the project, finally promoted to dashboard hero status.
3. **OS Container Privesc Accumulation chart** — Three Response Lanes card already led with cleaned 60–70% as of yesterday; periodicity-page side now matches. ✅
4. **Three Response Lanes card** — "Triggered" framed as workload reduction, not discrimination. ✅

### 3.2 What's still open (carry-forward)

1. **7-year per-framework chart** — pass 7 §6 #7. Not yet on the dashboard. The 30%-catch-rate per-framework backtest belongs alongside the 14-14-14 14-month workload chart so a reviewer can see both numbers without leaving the page.
2. **CWE-set version badge** — pass 7 §6 #8. Near the cross-framework chart; one line "DI CWE set v3 — 2026-04-22 (CWE-444 added) | 2026-04-23 (auth-bypass widened) | 2026-04-25 (CWE-434 removed)". Same content as the walkthrough §3a/§3b changelog box recommendation in §2.2 above; one source, two surfaces.
3. **Watch-list KPI band — exposure caveat** (new today, §1.5 #5). Add a footnote: "5/14 with ≥7 days exposure / 5/12 with ≥21 days. Spring AI cluster (5 entries added 2026-04-29) pending exposure." This is a 5-minute edit that closes the denominator-inflation reading.
4. **Three Response Lanes card** — annotate with the Mythos-page model-run-log link. The dashboard has the daily watch-list KPIs but doesn't surface the prospective per-CVE event log. One-line addition: "See [today's model run](glasswing.html#model-run) for per-event scoring."

### 3.3 The Mythos / model-run-log alignment (new this cycle)

The Mythos page §1 wires `data/model-run-log.json` correctly — schema-versioned, embedded between markers, page-script renders the latest run. Solid architecture. Three issues to surface:

1. **BioNeMo (CVE-2026-24164) inconsistency.** Run log says "NVIDIA is a Glasswing participant — flagged as probable participant self-scan." `config.json` `probable_participant_cves` has only the Cisco quartet. Either add BioNeMo (note: relaxes the strict HTTP-parsing-adjacent criterion to a trust-boundary criterion — defensible given the overall trust-boundary widening of NP, but the relaxation needs disclosing), or downgrade the run-log framing to "candidate — pending probable-participant criteria review."
2. **Bootstrap state** — only 1 run in the log. The §1 explanation correctly notes "after ~30 days of runs, prospective precision/recall by tier becomes statistically meaningful," but a reader landing on the page today sees a single bootstrap entry and may not realize the prospective claim is a future claim. Recommend a small banner: "Run log bootstrapping — 1 of ≥30 runs needed for prospective scoring; today's events are baseline."
3. **`kev_promotion_only` flag** — the ConnectWise CVE-2024-1708 entry in today's run is a 2024-vintage CVE newly promoted to KEV, not a new disclosure. The schema should distinguish these, otherwise prospective in-scope counts get inflated by KEV catalog curation. Add `kev_promotion_only: true` to the schema; default false; today's CVE-2024-1708 event flagged as such. This is a 10-minute schema addition + script update.

---

## 4. Cross-Page Architecture

### 4.1 Pages today

```
index.html         walkthrough — the argument                   ← front door
periodicity.html   workbook — the evidence                       ← deep dive
cve-reference.html audit trail — per-event JSON-derived rows     ← reproducibility
dashboard.html     live state — refreshed daily by agent         ← KPIs / watch list
glasswing.html     Mythos — speculative + prospective model run  ← intel + live feed
build-mechanics.html  how to operationalize                       ← practitioner guide
foss-sub7.html     scratch — sub-7 sensitivity test               ← experimental
evergreen.html     scratch — evergreening eval                    ← experimental
osv-exploitation.html scratch — OSV-based library analysis        ← experimental
```

That's 9 pages. The 5 production pages are coherent; the 3 scratch pages are appropriately marked. The Mythos page is the page whose role is most ambiguous (speculative analysis + live model-run feed + Glasswing tracking). With the model-run-log wired today, "live prospective scoring" is now its primary function — the speculative-Mythos-volume content could move to a sub-section or a separate page later.

### 4.2 Navigation (current state, after `7d23519` sticky page-nav)

Top nav across all production pages: Walkthrough · Periodicity · CVE Reference · Dashboard · Build Mechanics · Mythos. That's a stable left-to-right reading order (story → evidence → data → live state → how-to → intel). The scratch pages aren't surfaced in nav — correct.

### 4.3 Front door

**Index.html is and should remain the front door.** The "How to read this site" 5min/30min/verify/live/build-mechanics/AI-angle table at the top is the right onboarding. Today's only addition: the table should mention the live model-run on the Mythos page ("Live prospective scoring — Mythos page §1 — see today's CVEs scored against the model in real time").

---

## 5. Daily Scan — 2026-04-30

### 5.1 KEV adds

CISA catalog version 2026.04.24 (1,583 → 1,585) is unchanged from yesterday. Today's `kev-tracking.json` reports KEV count at 1,585 with the 2026-04-28 ConnectWise + Windows Shell adds already on board. **No new KEV entries 2026-04-29 or 2026-04-30.** April 2026 KEV total: 30 (4 promoted yesterday, none today).

CISA's BOD-22-01 deadline for the 2026-04-24 adds (SimpleHelp pair + Samsung MagicINFO + D-Link DIR-823X) is 2026-05-08; for the 2026-04-28 adds (ConnectWise + Windows Shell) is 2026-05-12.

**Watch-list cross-check:** no watch-listed CVEs were promoted in the past 24h. The 5/19 prospective hit rate is unchanged. Spring AI cluster (5 entries) is now the test cohort with 1 day of exposure.

**NP+DI candidate review** (per `kev-tracking.json` carry-over): only CVE-2024-1708 (ConnectWise) flagged today, and that's already on the watch list (sort of — the 2024 vintage is outside the standard watch-list 2026-onwards scope; the refresh agent flagged it for analyst review with "monitor" recommendation). No fresh np_di_candidates today.

### 5.2 NVD volume

April 2026 MTD: 5,720 (day 29 of 30). Extrapolated full-month: 5,920. Day-over-day NVD published delta (~140/day yesterday) below the running April average (~197/day) and continuing the late-April cooldown. April will land 5,800–5,950, in line with Q1 2026 (4,808–6,304) and consistent with steady-state. **Still no positive evidence of a Glasswing-driven volume shock.** Mythos volume thesis remains in the null. Mythos publication-latency caveat (4–8 weeks) means May is the next plausible window for a signal.

### 5.3 Mythos / Glasswing news

Three Mythos hits today, all 2026-04-29:

1. **TheHackerNews** — "Anthropic's Claude Mythos Finds Thousands of Zero-Day Flaws Across Major Systems." Restates the Mythos-found-thousands-of-bugs narrative. Products mentioned: multiple OSes, browsers, FFmpeg, OpenBSD, FreeBSD. No new CVEs attributed.
2. **arnav.au** — "What Anthropic Mythos Means for Cybersecurity." Long-form analysis blog post. No CVE attribution.
3. **The National (UAE)** — "What is Mythos: Anthropic's new AI model worries many experts." Mainstream international press picking up the story. No CVE attribution.

Adjacent AI-vuln-find news (not strictly Glasswing):

- **AISLE blog** (April 2026) — 5 of 7 OpenSSL April 2026 CVEs were AI-uncovered. AISLE is an independent AI security firm, not Mythos / Anthropic. The "AI scan tier" frame in periodicity.html still applies and the data point reinforces that AI-augmented vulnerability discovery is a multi-vendor phenomenon, not a Mythos monopoly.
- **Wiz Research** (2026-04-28) — disclosed CVE-2026-3854 GitHub Enterprise Server RCE (CVSS 8.7) using IDA MCP (AI-augmented reverse engineering). Out of probable-participant scope (third-party Wiz credit, not internal AI scan). Already noted in `kev-tracking.json` `vendor_advisory_flags`. Not Mythos. Worth flagging: this is the second non-Mythos AI-augmented bug-find this week; the AI-vuln-find category is real and broader than Mythos.

**No new Claude-credited CVEs in the past 24h.** Total Glasswing-attributable count: 283 (271 Firefox MFSA-30 batch, 9 wolfSSL, 1 each F5 NGINX Plus / FreeBSD / OpenSSL).

**Probable-participant carry-forward:**

- **CVE-2026-24164** NVIDIA BioNeMo Framework, CWE-502 deser RCE. NVIDIA is Glasswing participant. Bug class fits automated-scan pattern. *Not yet in `config.json` `probable_participant_cves`.* Two paths (see §3.3 #1): widen criterion + add, or downgrade run-log framing. **Recommend adding** with disclosed criterion-relaxation note (research/ML framework as trust-boundary surface — same logic the NP rule already uses for non-HTTP trust-boundary code). Companion CVE-2026-24165 same pattern.
- **CVE-2026-0234** Palo Alto Cortex XSOAR — was carry-forward through pass 6/7. Today's `kev-tracking.json` does not flag it. Refresh agent has moved on. **Recommend explicit close** with one-line note in `analyst-reports/rolling.md`: "CVE-2026-0234 closed without action: scope-call, integration vector (Microsoft Teams marketplace webhook) thin enough that automated-scan pattern is ambiguous."

### 5.4 Glasswing-participant cross-check on today's KEV adds

No KEV adds today, so no cross-check needed. The 4 entries added 2026-04-24 (SimpleHelp pair, Samsung MagicINFO, D-Link DIR-823X) are all non-participants. The 2 entries added 2026-04-28 (ConnectWise CVE-2024-1708, Microsoft Windows Shell CVE-2026-32202) — Microsoft is a Glasswing participant; CVE-2026-32202 is auth-bypass / spoofing on local desktop (not NP-applicable, not probable-self-scan), so no flag.

### 5.5 Net daily finding

Quiet day. The two material developments are commit-level rather than KEV-level: yesterday's analyst-backlog cleanup pass (commits `dc4af0d` + `d8bfafb`) closed 6+ items, and the FOSS sub-7 + Mythos-wiring work (commits `31f42fa` etc + `af4ffbb` etc) added new analytic substance without contradicting any prior finding. KEV catalog is unchanged from yesterday. NVD volume is consistent with the established April trajectory. Watch list is unchanged on hit-rate and unchanged at 5/19 promoted (with 5 new Spring AI predictions starting their exposure window). No participant-attributable CVE adds.

---

## 6. Punch List — Carry-Forward + New (post-pass-8)

Sorted by leverage:

**Highest leverage (today, ~30 minutes total):**

1. ☐ Add §3a sensitivity-of-the-discriminator addition referencing FOSS sub-7 (~10 min) — see §1.7
2. ☐ Resolve CVE-2026-24164 BioNeMo: add to `probable_participant_cves` with relaxation note OR downgrade run-log framing (~10 min) — see §3.3 #1
3. ☐ Close CVE-2026-0234 Cortex XSOAR carry-forward: add 1-line note in `rolling.md` (~5 min) — see §5.3
4. ☐ Add Mythos-bootstrap banner to glasswing.html §1 (~5 min) — see §3.3 #2

**High leverage (this week, ~2 hours total):**

5. ☐ Walkthrough §3a or §3b CWE-set changelog box (carry-forward; pass 7 §6 #4) (~20 min)
6. ☐ Mythos breach disclosure to walkthrough §12 — one sentence or explicit decision-to-skip (carry-forward; pass 7 §6 #6) (~10 min)
7. ☐ Walkthrough §4f duplication with periodicity §7 — one canonical home (carry-forward; yesterday §2.2) (~20 min)
8. ☐ Walkthrough §10 Reverse Proxy Myth — demote/move (carry-forward; yesterday §2.2 / pass 7 §6 #16) (~15 min)
9. ☐ Dashboard 7-year per-framework chart + CWE-set version badge (carry-forward; pass 7 §6 #7 + #8) (~45 min)
10. ☐ Watch-list KPI band exposure-weighted footnote (~5 min) — see §3.2 #3
11. ☐ Add `kev_promotion_only` flag to model-run-log schema + script (~10 min) — see §3.3 #3
12. ☐ FOSS sub-7 control-rate analysis: NP+DI false-positive rate on *unexploited* mediums in NP-classified packages (~30 min) — see §1.5 #1

**Medium leverage:**

13. ☐ §5 reframe as "what the filter correctly excludes" (carry-forward)
14. ☐ §6 reframe as supporting §3e (carry-forward)
15. ☐ §8a WAF-defensibility promote/merge with §9a (carry-forward)
16. ☐ Surface the 7-year canonical-manifest reconciliation as an in-page changelog entry (carry-forward; yesterday §0.3)
17. ☐ Surface in-container-privesc vs container-breakout distinction (carry-forward; pass 7 §6 #11)
18. ☐ Surface systemd's 12-of-21 LOCAL-CWE keyword inflation breakdown (carry-forward; pass 7 §6 #12)
19. ☐ Add SimpleHelp to server-side watch list (carry-forward; pass 7 §6 #10)
20. ☐ §15 EPSS 1-paragraph summary callout at top (carry-forward; pass 7 §6 / yesterday §1.4)

**Lower leverage:**

21. ☐ Pre-§1 hero block on walkthrough with 6-second pitch + cross-page nav cards
22. ☐ Add §14 "Limits of This Backtest" consolidating dispersed honest-disclosures
23. ☐ Canonicalize NP+DI definition to walkthrough §6; trim periodicity.html and cve-reference.html to summary-plus-link
24. ☐ 5th synthetic manifest from a less-canonical ecosystem (Rails, Go, Phoenix)

**Open from prior passes that are not directly addressable here:**

25. ☐ `tests/test_kev_classifier.py` with ~20 canonical examples
26. ☐ Triage the `other` bucket in `data/kev-layer-classifications.json`

---

## 7. Bottom line

Yesterday's six-item analyst backlog substantially closed. The dashboard zero-miss line (longest-running unfixed item, 6+ days) is fixed. The watch-list KPI band is now a dashboard hero. The OS-layer leak is closed across all surfaces. The EPSS hero `n=6` caveat is in. The Spring AI cluster is on the watch list — first prospective test for the auto-monitoring loop.

The new analytic substance — FOSS sub-7 + Mythos page model-run-log + cross-severity sensitivity test — is a real addition. The page-level honesty (134/135 NP, 0/4 KEV-confirmed clearing S+A, 25d KEV median for mediums comparable to C/H) is the kind of disclosure that makes the project defensible. It deserves a 3-sentence integration into walkthrough §3a so the sensitivity-of-the-discriminator finding is on the front door, not buried on a scratch page.

Two new inconsistencies introduced by today's work need closing:

1. The Mythos run-log says BioNeMo is a probable participant self-scan; `config.json` doesn't list it. Two pages disagree.
2. The watch-list KPI band's 5/19 denominator now includes 5 Spring AI entries with 12 hours of exposure. Honest scope is 5/12 with ≥21 days.

Both are 5–10 minute fixes.

The architecture (5 production pages + 3 scratch + Mythos) is the right shape and shouldn't be touched. Yesterday's note — "the work is tightening, deduplication, surfacing the reconciliation, and updating the headline numbers" — applies again today, with one fewer headline to update.

The CVE-2026-0234 carry-forward should be explicitly closed; three passes of inertia is enough.

— pass 8 / 2026-04-30
