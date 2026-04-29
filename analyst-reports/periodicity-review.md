# Periodicity Analysis & Walkthrough Restructuring Review

**Date:** 2026-04-29
**Author:** kev-analyst (scheduled run)
**HEAD at review:** `948128a` (today's refresh tracking commit; analytic HEAD `9ab06a0` Refresh: KEV 1583→1585 / NVD MTD 5371→5580)
**Predecessor pass:** yesterday's `periodicity-review.md` at commit `3aeaf85` (2026-04-28). Earlier rounds live as `periodicity-review-pass{5,6,7}.md` plus the 2026-04-25 reconciliation Q&A pair. This is the ninth analyst-side review.
**Scope:** brief in `analyst-reports/periodicity-review-brief.md`, plus the four pages it names (`docs/periodicity.html`, `docs/index.html`, `docs/dashboard.html`, `docs/cve-reference.html`). Bonus context: the in-flight 7-year forensic reconciliation work that landed since yesterday.

---

## 0. Headline (read this if you read nothing else)

**The brief is now three rewrite cycles out of date, and a 7-year data-reconciliation pass landed in the last 24 hours that the brief never anticipated.** The previous review (2026-04-28) declared the brief "two cycles out of date" and called for convergence/pruning rather than restructuring. Today's HEAD is 18 commits past that review and the work is now in a slightly different phase: the 7-year backtest got its own forensic audit (`b150630` "7-year manifest backtest divergence audit" + `40b3ff0`/`c83366b`/`bf9a8d0` reconciliation steps 1–3), the canonical 7-year manifest was promoted from a hand-curated 60-pkg / 176-version literal to a reproducible 58-pkg / 194-event cache, the evergreen Java section was rebased onto the same canonical, the cve-reference page was restructured into per-cohort sections (`4628111`), and a regression test (`tests/test_seven_year_npdi.py`) was added.

What this means for today's review:

1. **The substantive analytic content has moved past the brief.** Saying "the walkthrough is still the original observational analysis" — as the brief does — is now wrong by about 8 days and 80 commits. The walkthrough has been rebuilt around the threat-based prioritization model (NP+DI structure test + hacker S+A discriminator + DQ rescue), the 7-year backtest, the EPSS day-0/7/30 comparison, the WAF-defensibility axis, and the Cat 1/2/3 estate-maturity model. Sections 3, 4, 7, 8, 9 are post-periodicity content. The Operational Model lives on its own page (`build-mechanics.html`).
2. **Yesterday's four actionable items moved at varying speeds.** The dashboard "zero misses" line (item 1) still survives at line 166 — six days flagged, still unaddressed. The OS LPE-21-vs-10/12 leak (item 2) is partially closed: the periodicity §The OS Layer cadence-comparison table still shows 76% green, but the dashboard "Three Response Lanes" card now reads "~60–70% on the noise-cleaned LPE set" — that's progress on the dashboard side. The §4f duplication (item 3) is unchanged. The §10 Reverse Proxy Myth (item 4) is unchanged.
3. **The new 7-year forensic reconciliation rewrites the credibility envelope.** The previously-floating 60-pkg / 176-version manifest in prose, 54-pkg cache in `data/seven-year-manifest-events.json`, and 48-pkg literal in the chart have been collapsed onto a single canonical 58-pkg / 194-event manifest. Pass 7 flagged the divergence between 30%-catch (per-framework backtest) and 90%+-catch (real-manifest backtest) as the project's largest open inconsistency. That divergence is now resolved — but the resolution itself needs surfacing, because anyone who read pass 7 in the analyst-reports tree is going to ask why the headline numbers shifted.

Today's still-actionable items, ordered by impact:

1. **Dashboard line 166 "zero misses" framing is still live.** Six days flagged. Identical to yesterday's #1, plus pass 5's "highest urgency, ~5 min, must-ship-today." This is now the longest-running unfixed item in the review backlog and it's contradicted by the walkthrough §4b honest framing it sits beside.
2. **Periodicity §The OS Layer keeps the inflated 21/76% headline in the cadence-comparison table.** The dashboard Three Response Lanes card now leads with the cleaned 60–70% reduction; the periodicity page hasn't caught up. Both should match the walkthrough §7's "10–12 cleaned" framing.
3. **The 7-year reconciliation needs an in-page changelog entry.** The canonical numbers shifted (175→194 C/H, 34→40 NP+DI raw, 11 actually-exploited), and the real-manifest backtest is the document of record. Without a small "what changed and why" callout on `periodicity.html` and `cve-reference.html`, a reader who saw the prior numbers will assume p-hacking. The reconciliation report (`analyst-reports/2026-04-28-seven-year-data-reconciliation.md`) is excellent forensic work; it deserves a 2-paragraph surface in the published HTML.
4. **§4f content is still substantially duplicated** between walkthrough and periodicity. Same as yesterday's #3.
5. **§10 (Reverse Proxy Myth) is still redundant with §9a + Operational Model `#wafs`.** Same as yesterday's #4.

The walkthrough should NOT be restructured. It is converged. The work is tightening, deduplication, surfacing the reconciliation, and updating the headline numbers that still inherit the overstated version.

---

## 1. Assessment of the Periodicity Analysis (current HEAD)

### 1.1 Is the NP+DI methodology sound?

**Mostly yes, with one new wrinkle introduced by today's reconciliation.** Pass 7 named the structural soft spots (CWE classification dependency, NP-classification judgment-calls on socket.io/passport vs. pg/redis, 7-day patch-merge knob, pre-EPSS-coverage caveat); none of those changed today and the recommendations from pass 7 / yesterday's review still apply.

The new wrinkle is from `analyst-reports/2026-04-28-seven-year-data-reconciliation.md`. Three sources had three different headline numbers (chart 160, data file 175, prose 223) until today's reconciliation collapsed them onto the canonical 58-pkg / 194-event manifest. The fix is good — it removes the floating-prose-vs-floating-data state — but it introduces a different question the walkthrough should address: **which manifest is the canonical 7-year backtest?**

The pass-7 finding was that the per-framework backtest (`data/seven-year-per-framework.json`) showed a 30% catch rate (3 of 10 caught) on Spring+Django combined, while the real-manifest backtest in periodicity §7 showed ~90% (5 of 8 in NP+DI raw, 8 of 8 in NP+DI+DQ). That's a startling delta and the walkthrough §4f currently leans on the higher figure. The reconciliation didn't merge those two analyses — it canonicalized the *real-manifest* analysis. The per-framework analysis is still in the repo and still shows the harder result.

The honest position here: **the per-framework synthetic backtest is a different manifest with a much narrower NP package set and fewer adjacent rebuilds, so it produces a worse per-framework catch rate, and that's not contradicted by the higher real-manifest rate.** They're measuring different things. But the walkthrough §4f and periodicity page §7 should say so explicitly. A reader who spots both numbers in the repo will conclude one is being suppressed; a one-paragraph note ("the 12-month synthetic per-framework run measures a smaller manifest in a tighter window; the 7-year canonical 58-pkg manifest measures the production-shape estate over a longer horizon — the catch rates are not directly comparable") closes that gap cheaply.

The pass-7 recommendation to add a CWE-set versioning changelog is still outstanding. Today's reconciliation makes it more urgent, not less — three of the canonical manifest's NP+DI numbers shifted today (175→194, 34→40, etc.) and the changelog needs a row for it.

### 1.2 Is the cross-framework validation convincing?

**Yes for what it claims now; the canonical-manifest unification helps.** Yesterday's review correctly noted the credibility ordering: lead with the 7-year real-enterprise backtest (production manifest, real exploitation evidence), treat the 14-14-14 12-month synthetic stacks as "and here's why this isn't a Java-and-Tomcat artifact." Today the 7-year real-enterprise backtest is even more defensible because it now has a reproducible cache (`scripts/build_seven_year_manifest_events.py` + `--check` mode, currently failing in the refresh-agent environment due to a hardcoded iCloud cache path — see error log in `kev-tracking.json`).

The synthetic-manifest 14-14-14 convergence is still suspicious-in-a-good-way (pass 5/6/7 §1.2/1.5 covered this), and the recommendation to add a 5th-or-6th synthetic manifest from a less-canonical ecosystem (Rails, Go, Phoenix) — which would either strengthen or expose the convergence — is still worth doing.

Devil's-advocate angle the user preferences ask me to surface: **the 58-pkg canonical manifest is still authored by the same hand that authored the original 48-pkg cache.** Today's reconciliation merged three internally-consistent-but-divergent versions of the same analyst's work into one. That's a credibility upgrade against the prior state ("which number is real?") but it's not a credibility upgrade against the bigger circularity worry ("are the manifest contents themselves overfit to the events the page wants to catch?"). The defensible answer is: the manifest came from a real Spring portfolio survey that long predates the 7-year backtest exercise (the original `analysis-scripts/spring_manifest_analysis.py` was the seed), and the 14 additions in today's reconciliation step 1 (commit `40b3ff0`) are documented with rationale. But "authored by the same analyst with no independent reviewer" remains a structural fact the page should own.

### 1.3 Is the OS chaining / kill-chain framing correct?

**Directionally yes; the headline-leakage problem is partially closed and partially not.** The walkthrough §7 reads cleanly today (10–12 cleaned LPE-relevant + ~50 NVD-noise callout). The dashboard "Three Response Lanes" card now leads with "60–70% on the noise-cleaned LPE set" — that's the cleaner framing. The remaining leak is on `periodicity.html`:

- **§The OS Layer hero KPI (line ~583):** still shows "21 LOCAL vector (privesc)" — the inflated number, no caveat in the hero.
- **§The OS Layer cadence-comparison table (line ~633):** still shows monthly = 5 / 76% reduction in green; the cleaned-figure caveat sits in a footnote one block below.
- **The chainingChart (`chainingChart` canvas):** The chart itself is on both the periodicity page and the dashboard. The periodicity-page chart's exploit-marker overlay was just restored today (`2af1344` "periodicity §7 chart: restore exploit-marker overlay"); a one-line annotation that the y-axis includes NVD keyword noise would close the dashboard-vs-periodicity inconsistency in five minutes.

The fix is the same as yesterday's recommendation #2: lead with the cleaned number on every surface, demote the raw 21 to a footnote. The dashboard side is now done. The periodicity page is the remaining surface.

### 1.4 Does the EPSS / external-validation analysis hold up?

**Strongly. No new content here today; the §15 EPSS rebuild from 2026-04-26/27 is still the strongest analytic block in the page.** Yesterday's review covered this in detail; nothing has changed in the EPSS section in the last 24 hours that I can see.

The pass-7 recommendation — single-sentence parenthetical in the EPSS hero callout that the 34.7-day average is computed on n=6 with EPSS coverage — is still outstanding. So is the recommendation to add a 1-paragraph summary callout at the top of §15 to break up the now-7-card-long surface area. Both are 5-minute edits.

### 1.5 Devil's-advocate: what could undermine the conclusions?

The user preferences ask me to push the other side. I'll keep this short — pass 7 §1.5 covered the five strongest hostile angles in detail. Today's incremental adversarial points:

1. **The 7-year reconciliation is the kind of work a hostile reviewer can paint as "cleanup-after-the-fact."** A skeptic reading the reconciliation report ("three sources, three numbers, all internally consistent but divergent") could fairly say: the prose was authored to produce a specific story, the data file was reproducible but at a different manifest, the chart was a third version. The fix today merges them into one canonical, but the merge is happening 2026-04-28/29 and the prose §7 numbers are dated to 2026-04-26 (commit `efc8f3d`). The defensible response: the reconciliation was a forensic audit, the canonical is reproducible, the unification ran through a regression test and a 408-assertion evergreen test. That's the right shape of response. But the temporal ordering — author the prose first, fix the data later to match — is something a hostile reader will notice and the walkthrough should acknowledge that the canonical manifest was finalized 2026-04-28 in a brief reconciliation note.
2. **The watch-list hit-rate (5/14) is the project's strongest piece of forward validation and it's still buried.** Today's daily scan: stable at 5/14. Cisco SD-WAN's 46-day exploitation-to-KEV gap suggests the four Cisco probable-participant-self-scan entries could land in KEV in late May. The Thymeleaf SSTI pair, n8n Ni8mare, and wolfSSL pair (the other 5 still WATCHING) all carry watch list ages > 9 days — increasingly tight tests of the predictive claim. A skeptic could fairly point out that the 5/14 rate is presented as monotonic prospective validation when the actual base rate (how many random HTTP-parsing C/H disclosures from the same window also reached KEV?) has not been reported. The walkthrough makes the prospective-validation claim implicitly; a denominator comparison would land it more honestly.
3. **The "structure filter is never worse than EPSS on any event" claim has had no live test in the last 24 hours.** Today's two new KEV adds (CVE-2024-1708 ConnectWise, CVE-2026-32202 Windows Shell) both fit that frame correctly: the ConnectWise add is a path-traversal NP+DI textbook case (caught) and the Windows Shell auth-bypass-via-input is desktop/local (correctly outside scope). But "no live failure today" is not the same as "stress-tested." The Spring AI cluster disclosed 2026-04-27 (5 CVEs, all NP+DI candidates per today's `np_di_candidates`) is exactly the kind of event the watch list should be tracking — none of the five are on it as of today. That gap is small enough to fix manually, but it's a place where the auto-monitoring loop missed a clean prospective-validation opportunity.

### 1.6 What's new since yesterday's review (commit `3aeaf85`)

Yesterday's review applied. The 4 obvious fixes from that review are in mixed states (see headline). Today's HEAD is 18 commits past `3aeaf85`, with the substantive changes:

- **7-year forensic reconciliation** (commits `b150630`, `40b3ff0`, `c83366b`, `bf9a8d0`) — divergence audit between three different 7-year backtest sources; canonical 58-pkg / 194-event manifest established; regression test added.
- **cve-reference per-cohort rebuild** (commits `c33fdb2`, `4628111`) — restructured into per-cohort sections (12-month per-framework, 7-year manifest, 11-actually-exploited, hacker-tier rounds, WAF judgments, DI-widening reclassification, watch list, legacy static rows). This is the audit-trail-document-of-record reshape pass 5/6/7 had been asking for. Significant credibility upgrade.
- **Walkthrough sidebar surfaces §4 subsections** (`a60b76f`) — 4a–4f now show in left nav like §2a–c. Right call; §4 is the heaviest section.
- **Top page-nav now sticky across all pages** (`7d23519`). Polish but cumulatively raises navigation quality.
- **Walkthrough lead paragraph CTA buttons removed** (`977c4f3`). Lighter front door.
- **Operational Model rework** (`54a43cf`, `414bee1`, `e45ebc8`, `95cafb9`) — section reorder, redundant sections deleted, automatic-dependency-update content added, hero summary expanded. This is the same convergence work yesterday's review described; another day of polish.
- **Refresh agent run today** (`9ab06a0`, `948128a`) — KEV 1583→1585, April KEV 28→30, NVD MTD 5371→5580, extrapolation 5755→5979.

Net analytic substance: the 7-year reconciliation is the most important change. It removes the highest-priority *factual* inconsistency in the repo and replaces it with a single canonical that's reproducible and tested. Now the walkthrough's §4f numbers should be surfaced from `data/seven-year-manifest-events.json` rather than literal-hardcoded — that's a separate refactor (the data-amplitude architecture point from REVIEW-FINDINGS.md), not an urgent one.

---

## 2. Walkthrough Restructuring Recommendations

The brief's mental model — "the walkthrough is still the original observational analysis; recommend a section outline" — is wrong against today's HEAD by ~8 days and ~80 commits. The walkthrough has been restructured. The remaining recommendations are tightening, not surgery.

### 2.1 Current section structure (already good — same as yesterday)

```
1.  The Problem                                       — opener, three-app-profiles framing
2.  The First Clue: Where Exploits Actually Land      — observational analysis (stack layers, NP, libraries)
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
11. Exploit Watch List + Thesis Challenge
12. Caveats
```

This is a coherent argument: problem → observational evidence → model → validation → operational response → live experiment. Don't restructure it. The §4 sidebar surfacing committed today (`a60b76f`) is the right shape for the heaviest section.

### 2.2 What to keep, cut, move (delta vs. yesterday)

**Keep as-is:**

- §1, §2, §3, §4 (excluding the duplication issue below), §7 (cleaned), §8, §9, §11. All converged.
- "How to read this site" 5min/30min/verify/live/build-mechanics/AI-angle table at top. Right onboarding.
- §11 watch list — this is the live validation experiment.

**Tighten (carry-forward from yesterday):**

- **§4f duplication.** Strategy efficiency table + 13-library NP+DI table also live on `periodicity.html` §7. Pick one canonical home (recommend `periodicity.html`, the evidence document) and let §4f show the headline summary row + "Detail on the periodicity page" deep link. **Yesterday's review made this recommendation; not yet applied.**
- **§5 (Why Most Criticals Don't Get Exploited).** Re-anchor as "what the filter correctly excludes" — a §3-aligned restatement. The opening sentence: "The threat-based filter excludes ~93% of C/H CVEs. Here's why that's defensible."
- **§6 (Time-to-Exploit).** Re-anchor as supporting §3e ("hidden cost of not filtering"), not as standalone thesis. The 251d→11d→3d framing is striking and should stay; the implication "30-day patch cycle is broken" was the *old* argument for emergency response. The new argument (NP+DI + hacker S+A reduce emergency events to 2–6/year, supplements absorb the rest) makes the time-to-exploit data into supporting evidence.
- **§8a (WAF defensibility).** Strong subsection. Consider promoting to a top-level §8 successor or merging with §9a (WAF Dividend) to avoid two WAF passes in the same page.
- **§10 (Reverse Proxy Myth).** Now redundant with §9a + Operational Model `#wafs`. Demote to callout in §9a, or move to Operational Model entirely.

**New tighten item (today):**

- **§4f canonical-manifest reconciliation note.** Add 2-3 sentences at the top of §4f noting that the 58-pkg / 194-event manifest is now the canonical 7-year backtest (resolved 2026-04-28 from three previously-divergent sources), and that the per-framework synthetic backtest in `data/seven-year-per-framework.json` measures a different manifest and therefore reports different catch rates. This forestalls the "p-hacking via manifest selection" reading without burying the explanation.

**Cut:**

- "Use this tomorrow" checklist at end of §9 (lines ~810–820) duplicates Operational Model. Either link to Operational Model or trim to 3-bullet headline.
- §9 "Track your filter's hit rate over 6 months — it should produce zero misses." Now contradicted by §4f 7-year data showing 1 union-miss + 2 pre-2018 absorbed-by-supplements. Reword: "few misses, all in the documented blind-spot patterns."

### 2.3 Where the periodicity findings fit (already integrated)

- §3 introduces the model.
- §4 says "and here are the cross-framework results" with the 14-14-14 + 7-year backtest.
- §8 says "and here's how it compares to existing exploitation signals (EPSS, KEV, etc.)."
- §9 says "and here's how to operationalize it given your estate's maturity."

This is the right integration. The periodicity page is the deep-dive evidence document; the walkthrough is the argument. **The architectural pattern works; don't fold periodicity back in.**

### 2.4 The "zero-miss" framing — sixth-day status

Yesterday's review flagged this. Today's status is materially unchanged:

- **Walkthrough §4b honest framing:** in place ("N=1 doesn't differentiate strategies from random").
- **Walkthrough §4a hero KPI:** "10/11 7-year backtest catch (union NP+DI+DQ ∪ Hacker S+A)". Today's reconciliation moved the canonical from 11 to 11 (unchanged on the catch side); the hero is honest. The "if you run both methods" caveat is still in the label only — make it explicit: "10/11 caught directly, 1/11 absorbed by supplements (B-tier OpenWire RCE)".
- **Walkthrough §9 quick-checklist:** Still says "track your filter's hit rate over 6 months — it should produce zero misses." Same as yesterday. Same fix.
- **Walkthrough §12 Caveats:** Still says "12 months of zero misses is strong but not conclusive." Same as yesterday. Same fix: reword to "12 months of N=1 is statistically uninformative; the 7-year backtest is where scoring happens."
- **Dashboard line 166:** **Still the original 12-month-window-only claim, six days flagged.** "Reduces rebuild-trigger dates by 64–86% with zero misses — no filtered-out CVE has appeared in CISA KEV." Either scope it ("zero misses in the 12-month synthetic-stack window") or replace with the 7-year backtest result (10/11 union, 1 absorbed).

This is the single highest-leverage 5-minute edit available right now and it has been the highest-leverage 5-minute edit since pass 5 (2026-04-24).

### 2.5 Periodicity page should remain separate

Confirmed against today's HEAD. The architectural pattern — walkthrough = argument, periodicity = evidence, cve-reference = audit trail, dashboard = live data, Operational Model = how-to, Mythos/glasswing = intel assessment — is the right shape. Today's `cve-reference.html` per-cohort rebuild reinforces this; the page is now a much cleaner audit-trail document.

---

## 3. Dashboard Updates

### 3.1 What to fix (carry-forward from yesterday)

1. **Line 166 banner:** scope or replace the "zero misses" claim. **Yesterday's #1; pass 5's "5-min must-ship-today"; six days unaddressed.** Recommend: *"Reduces rebuild-trigger dates by 64–86%. The 12-month synthetic stacks have zero misses (N=1 in window — workload measurement, not discrimination). The 7-year canonical 58-pkg manifest catches 10 of 11 actually-exploited events directly; 1 is absorbed by floor-sweep + threat-intel supplements."*
2. **OS Container Privesc Accumulation chart:** annotate y-axis with the cleaned 10–12 figure or replace 21 with the cleaned number. Same fix as yesterday's #2; partially closed (Three Response Lanes card now leads with 60–70%).
3. **Three Response Lanes card content:** the lane framing is correct. The "Triggered" card now correctly shows "14 events/year → 2–6 after filter" — that's a reduction-of-rebuild claim, not a discrimination claim. Good.

### 3.2 What to add (carry-forward from yesterday)

1. **Watch-list hit-rate KPI tile.** Stable at 5/14 promoted to KEV (Marimo, SharePoint, ActiveMQ, Adobe Acrobat, Defender BlueHammer). Cleanest single addition; still undersold. **Yesterday's #6.**
2. **EPSS-marginal hero stat.** "At EPSS ≥ 0.50, NP+DI absorbs 41 of 44 would-be EPSS triggers" — too good to be invisible from the dashboard.
3. **Day-0 catch comparison.** 4-bar chart: NP+DI raw / NP+DI+DQ / Hacker S+A / EPSS ≥ 0.10 day-0 catch on the 7-year backtest. Single chart; ~4 bars; kill-shot framing.

### 3.3 What's now stale / OK to remove

- The "0 misses in 12 months" line in line 166. Either scope or replace.
- No new stale content surfaced today.

### 3.4 What to leave alone

The dashboard's primary value is fast-loading data charts that auto-refresh daily. Don't make it a second walkthrough. Layer rates, HTTP-parsing lift, TTE, CWE families, ransomware, top products, and searchable KEV table all stay. Cross-framework chart and OS privesc chart are the right additions; don't add more periodicity charts.

### 3.5 New today

The dashboard didn't change in the last 24 hours (today's refresh agent updated KPI tiles via the auto-refresh JSON, not the static HTML). The remaining edits are unchanged from yesterday.

---

## 4. Cross-Page Architecture

### 4.1 Page roles (recommended; mostly already in place)

| Page | Role | Audience |
|---|---|---|
| `index.html` | The argument. Problem → model → validation → operational response. | New reader, sets the case. |
| `periodicity.html` | The evidence. Reproducible cross-framework + 7-year backtest with supporting tables and per-event reasoning. | Skeptical reader who wants to verify or adopt. |
| `cve-reference.html` | The audit trail. Per-cohort sections (newly restructured today). | Reviewer, adopting team. |
| `dashboard.html` | The live scorecard. Daily-refreshed data. | Operational reader, recurring visit. |
| `build-mechanics.html` (Operational Model) | The how-to. Cat 1/2/3 estate maturity, BAU vs floor sweeps, WAFs as bridge, get-newest builds. | Implementer. |
| `glasswing.html` (Mythos) | Intelligence assessment, labeled speculative. | Reader interested in the AI-vulnerability-research angle. |
| `evergreen.html` (Java section rebased today), `osv-exploitation.html` | Auxiliary analyses. | Internal / curiosity. |

This structure exists and is now sharper after today's `cve-reference.html` per-cohort rebuild and the evergreen Java rebase to canonical. The work is making sure each page stays in lane — the §4f duplication between walkthrough and periodicity is the most visible remaining offender.

### 4.2 Front-door experience

The walkthrough is the front door. The "How to read this site" table is the right onboarding pattern; today's CTA-button removal (`977c4f3`) makes the lead lighter, which is good.

Two improvements still worth considering (carry-forward from yesterday):

- **A "what's new since last quarter" callout** for repeat visitors. The site presents as a single document but is actually a moving analysis with weekly-or-better substantive updates. Today's reconciliation is exactly the kind of change a "what's new" callout should mention.
- **A versioning indicator on the model.** "Threat-based prioritization model v1.2" with a CWE-set changelog. Pass 5's recommendation; still missing. Pass 7 strengthened it. Today's reconciliation makes it more urgent — three numbers shifted today, and the page should disclose that.

### 4.3 Navigation

Top-nav (Overview / Periodicity / Operational Model / Evergreening / Mythos / Dashboard / CVE Reference) is consistent across all pages and now sticky (`7d23519`). Keep.

The walkthrough's left sidebar at 12 sections plus the §4a–f subsections (newly surfaced today) is at the upper end of scan-friendly. After the §6 → §3e fold and §10 → §9a callout proposed in §2.2, the sidebar would have 10 main sections, which is better.

---

## 5. Summary of Recommended Actions (ordered by impact)

1. **Scope or replace the "zero misses" claim on the dashboard banner.** Six days unaddressed. Pass 5's "5-min must-ship-today." This is the longest-running unfixed item in the review backlog.
2. **Use the cleaned LPE figure (~10–12, 60–70% reduction) as the headline on `periodicity.html` §The OS Layer cadence-comparison table and on the periodicity-page chainingChart.** Walkthrough already cleaned; dashboard Three Response Lanes card now cleaned; periodicity page is the remaining surface.
3. **Add a 7-year reconciliation callout to `periodicity.html` §7 and the cve-reference page** explaining that the canonical manifest was unified from three previously-divergent sources on 2026-04-28; surface the audit trail (`analyst-reports/2026-04-28-seven-year-data-reconciliation.md`) so a reader who saw prior numbers understands what changed and why.
4. **Trim walkthrough §4f.** Move the per-library NP+DI table to periodicity.html; keep the strategy table + headline row + deep link.
5. **Re-anchor §5 and §6** as supporting §3, not standalone theses.
6. **Fold §10 (Reverse Proxy Myth)** into §9a or move to Operational Model.
7. **Add a watch-list-hit-rate KPI tile to the dashboard** (5/14 promoted to KEV). Cleanest prospective-validation surface; still undersold.
8. **Add the auth-bypass-widening CWEs (287, 289, 306, 345, 693, 863, 1321) to the §3b DI table explicitly** in a banded section with cleaner formatting.
9. **Add a worked hacker-tier example** to §3d (Spring4Shell as S/A, Tomcat HTTP PUT as B, Multer DoS as D).
10. **Publish a CWE-set versioning changelog** (pass 5 §1.1; today's reconciliation makes this more urgent — three numbers shifted today).
11. **Add a sensitivity table for the 7-day patch-event merge window** (0d/3d/7d/14d). One paragraph in periodicity §7. Closes a curmudgeon objection cheaply.
12. **Surface the Spring AI 2026-04-27 cluster on the watch list** (CVE-2026-40967 vector-store FilterExpressionConverter, CVE-2026-40978 CosmosDBVectorStore SQLi, plus the three companions). Today's `kev-tracking.json` flagged them as NP+DI candidates with `recommendation: add_to_watchlist`. None are on the live watch list yet. Manual add closes a clean prospective-validation opportunity.

The walkthrough should NOT be restructured. It is converged. The work is tightening, deduplication, and updating headline numbers that still inherit the overstated version.

---

## 6. Daily Scan (2026-04-29)

### KEV
- catalogVersion **2026.04.28**, total **1,585**, April KEV **30**. Two new entries today (2026-04-28 dateAdded):
  - **CVE-2024-1708** — ConnectWise ScreenConnect path traversal (CWE-22) → RCE. Original SlashAndGrab cluster (Black Basta / Bl00dy ransomware, Feb 2024). NP+DI textbook fit. Likely retroactive KEV catalog cleanup, not fresh exploitation. Today's `kev-tracking.json` flagged for watch list addition.
  - **CVE-2026-32202** — Microsoft Windows Shell auth bypass (CWE-693, protection mechanism failure). Microsoft confirmed active exploitation at Patch Tuesday. Auth-bypass-via-input but desktop/Windows-Shell-local, not HTTP-adjacent. Correctly outside NP+DI scope.
- Watch-list hit-rate stable at **5 of 14 promoted to KEV** (Marimo CVE-2026-39987, SharePoint -32201, ActiveMQ -34197, Adobe Acrobat -34621, Defender BlueHammer -33825). 9 still WATCHING:
  - Server: Thymeleaf SSTI pair (-40477, -40478, PoC), wolfSSL pair (-5194, -5501, none), n8n Ni8mare (-21858, functional), Cisco ISE cluster (-20180, -20186, -20147, none), Cisco Webex (-20184, none).
  - Cisco SD-WAN's 46-day exploitation-to-KEV gap suggests the four Cisco probable-participant-self-scan entries (ISE x3 + Webex SSO) could land in KEV around late May. They've been WATCHING since mid-April.
  - n8n Ni8mare has been WATCHING for 10 days. Horizon3's "zero customer impact" finding from 2026-04-19 continues to be the cleanest piece of disconfirming evidence for the "PoC → KEV in days" heuristic.

### NVD volume
- April MTD = 5,580 (day 28 final, post-backfill). Day-over-day +209 CVEs as NVD backfilled late Apr-28 publications. April pace normalizes at ~199/day. Extrapolation 5,979 (was 5,755 yesterday — moved +3.9% on backfill).
- Week-17 (Apr 20–26) closed final at 1,469. Week-18 (Apr 27–May 03) partial through Apr-29 04:00Z: 428 entries, on pace.
- April will close ~5–10% below March (6,304) and within the Q1 churn band (4,808–6,304). **Twenty-eight days of post-Glasswing-launch volume continues to argue against the "AI is flooding CVE" framing.** The counter-argument continues to live: NVD assignment latency 4–8 weeks means a Mythos surge from April could still be in the publishing pipeline. Cannot distinguish "no surge" from "surge in pipeline" until mid-to-late May.
- April 9 Tomcat batch (7 CVEs all-NP, 6 of 8 DI) remains the only suggestive signal in the window. The Spring AI April 27 cluster (5 CVEs, all NP+DI candidates) is a second suggestive signal — same coordinated-release shape as the Tomcat batch, no Mythos attribution in advisories.

### Glasswing / Mythos
- Glasswing CVE count holds at **283** (271 Firefox 150 / MFSA 2026-30, 9 wolfSSL, 1 each F5 NGINX Plus / FreeBSD / OpenSSL). No new participant products surfaced.
- Claude-credited known: **6** (CVE-2026-4747 FreeBSD NFS autonomous, CVE-2026-5194 wolfSSL cert validation Mythos-Preview-assisted, CVE-2026-5588 Bouncy Castle Carlini+Claude, plus three Firefox 150 entries -6746/6757/6758). No new credits in 24h.
- **Researcher-assisted (NOT Mythos-attributed):** calif.io published CVE-2026-27654 (NGINX OSS ngx_http_dav_module heap buffer overflow via Destination header underflow). Same pattern as CVE-2026-34197 (ActiveMQ Claude-assisted via Horizon3). Today's `kev-tracking.json` flagged this for analyst review — recommendation is to NOT add to `claude_credited_cves` (researcher-assisted, not Anthropic-credited Mythos disclosure). I concur with that call. A separate `researcher_assisted_cves` bucket might be worth maintaining for reporting cleanliness.

### Glasswing-participant cross-check (today)
- **NVIDIA BioNeMo cluster:** CVE-2026-24164 + CVE-2026-24165, both insecure deserialization (CWE-502), both internally disclosed by NVIDIA, no third-party credit. Pattern matches probable-participant-self-scan profile (NVIDIA is a Glasswing participant). Today's `kev-tracking.json` flagged as `meets_self_scan_criteria: possibly`. Monitor; if the second one publishes with same disclosure shape, consider promoting to the probable-participant-self-scan table on the dashboard. Currently four entries on that table (Cisco cluster); BioNeMo would be a useful diversification.
- **Spring AI 2026-04-27 cluster** (CVE-2026-40966/40967/40978/40979/40980): VMware/Pivotal-Spring disclosure, not AI-attributed but classic NP+DI candidates (SQL injection in CosmosDBVectorStore.doDelete, FilterExpressionConverter injection, SpEL/JSONPath injection). Spring is not a Glasswing participant per current list. Worth adding to the watch list as five separate entries — or as a single "Spring AI vector-store cluster" bucket — even if not Glasswing-attributed.

### Notable / non-routine
- **The watch-list cadence (5 promotions in ~6 weeks) is now stable enough to surface as a dashboard KPI** — recommendation #7 above. Same as yesterday.
- **The Tomcat batch (April 9–15) and Spring AI batch (April 27) both look like coordinated-release events of accumulated findings.** Neither carries Mythos attribution; both are exactly the cluster shape an AI-assisted scanning campaign would produce. The same shape would also result from any focused fuzzing campaign, AI-assisted or not. Cannot distinguish from current data.
- **No KEV-level signal that overturns the cumulative pattern.** April KEV remains dominated by enterprise-edge products (Fortinet, Ivanti, SharePoint, Exchange, ActiveMQ, NetScaler, D-Link, Samsung, SimpleHelp, Cisco SD-WAN, ConnectWise ScreenConnect retroactive add). The HTTP-parsing-adjacent share is ~50% of April KEV, in line with the long-run ~47% baseline.
- **Refresh agent error today:** `tests/test_seven_year_npdi.py` failed in the refresh-agent environment due to a hardcoded iCloud cache path (`scripts/build_seven_year_npdi.py` and `scripts/build_cve_reference.py` reference `/sessions/bold-nice-euler/mnt/vulnerability\ analysis/cached-data`). The test infrastructure isn't agent-portable. This is a minor environmental issue, not a data issue; data deliverables for today's refresh did not touch the affected JSON. Recommend parameterizing the cache path or adding a graceful skip when the cache isn't reachable. Already noted in `kev-tracking.json.errors`.

---

*End of review report. Recommendations are advisory; no HTML edits made by this run per the task brief instructions. Today's pass overwrites `periodicity-review.md` (was commit `3aeaf85`, 2026-04-28); prior pass5/6/7 reports remain at their existing paths. The 2026-04-28 forensic reconciliation report (`analyst-reports/2026-04-28-seven-year-data-reconciliation.md`) is the canonical reference for today's manifest unification.*
