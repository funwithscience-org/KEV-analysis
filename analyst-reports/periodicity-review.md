# Periodicity Analysis & Walkthrough Restructuring — Internal Review

**Author:** kev-analyst (scheduled review pass)
**Date:** 2026-05-01
**Brief:** `analyst-reports/periodicity-review-brief.md`
**Inputs reviewed:** `docs/periodicity.html`, `docs/index.html`, `docs/dashboard.html`, `docs/cve-reference.html`, `config.json`

---

## TL;DR

The periodicity analysis is the strongest piece of work in this project. The cross-framework headline (14-14-14 → 2-6 NP+DI), the seven-year manifest backtest (10/11 caught by union of NP+DI+DQ ∪ hacker S+A), and the EPSS marginal-cost decomposition each clear the bar for a defensible "triage policy" claim. The page's biggest weakness is that several headline phrasings — particularly "zero misses across 113 non-trigger CVEs" — read like a discrimination claim when they are actually a workload claim with N=1 in-scope exploited CVE. The page already says this twice; it needs to say it once, in the headline, and stop.

The walkthrough is in better shape than the brief implied — it has clearly been rewritten since the brief was drafted (no §9 "Patch SLA Framework" remains; §9 is now Cat 1/2/3 estate maturity). The remaining work is **narrative reordering**, not content insertion. The walkthrough currently runs observation → model → validation → why-criticals-don't-get-exploited → time-to-exploit → kill-chain → external-validation → operations. That is a tour of the receipts in roughly the order they were produced. A reader-first ordering — observation → model → validation → operations, with survivorship and time-to-exploit folded into the motivation up front — is shorter and tells the prescriptive story the brief wants.

The dashboard needs the seven-year strategy-efficiency table (raw / +DQ / hacker S+A / union vs. all-C/H), a strategy-comparison chart, and a header reframing that pulls the operational claim ("10/11 caught union; 91% effectiveness, 3.2x overhead per real exploit") into the hero. periodicity.html should remain separate as the methodology / receipts page. cve-reference.html should remain separate as the audit trail.

---

## 1. Assessment of the periodicity analysis

### 1a. What is sound

**The seven-year backtest is the heart of the work.** 194 critical/high CVEs, 11 actually exploited (KEV ∪ MSF ∪ EDB), four strategies scored on the same cohort. Strategy efficiency is comparable across rows (patch events, raw triggers, exploits caught, overhead per exploit). The numbers reconcile internally: 5/11 raw → 8/11 with DQ → 9/11 hacker S+A → 10/11 union → 11/11 with floor-sweep + threat-intel + window-extension on the 2017 Tomcat pair. This is the kind of small-N audit that is easy to do badly and is being done well.

**Cross-framework reproduces the workload claim.** Spring 14, Node 14, Django 14, Netty 3 all-C/H trigger dates → 5, 2, 6, 1 NP+DI. Three different ecosystems (Maven, npm, PyPI) and a fourth Java stack with a different I/O model; the 64-93% reduction holds. The Netty result is particularly useful — it picked up on a CWE-444 request-smuggling bug that wouldn't have triggered without the post-review widening of the DI set. That's the kind of result that survives a "did you fit your filter to the data" challenge.

**EPSS marginal-cost decomposition is the right framing.** The standalone count (33 / 21 patch events at EPSS ≥ 0.10 / 0.50) is what every EPSS-only shop sees. The marginal count after NP+DI+DQ (3 / 1) is the honest add-on cost. This sells the model as "fire on disclosure day for structural reasons; sweep with EPSS for the floats." That is a defensible operational story and it lines up with the FIRST.org guidance (EPSS + CVSS + context, not EPSS alone).

**Honest about the two big confounders.** The page calls out (i) N=1 in-scope exploited CVE in the 12-month synthetic stacks, so "zero misses" is workload not discrimination; (ii) NVD keyword noise inflates the OS LPE count from 21 to ~10-12. Both caveats are visible in the body text. That said — see §1b — they should be in the headline, not buried.

**WAF-defensibility axis is a useful addition.** Most triage frameworks pretend the perimeter doesn't exist. Carving WAF-defensibility out as a separate axis on actually-exploited events is the right move; it lets the reader see which "B-tier handled by supplements" events are actually held by the perimeter vs. carried by floor-sweep alone.

### 1b. Where I'd push back

**"Zero misses" overclaims and the page knows it.** The conclusion says "Zero of the 34 skipped app-layer events appeared in KEV." On the 12-month synthetic stacks, exactly one CVE was actually exploited (Django 64459, ExploitDB-only). With N=1 you cannot demonstrate discrimination of any classifier; the filter could be "always fire" or "never fire" and "zero misses" would still be true ~50% of the time at this sample size. The page acknowledges this in §3 ("Honest caveat on the 12-month synthetic stacks") and §15. It then re-uses "zero misses across 113 non-trigger CVEs" three more times in headline-position callouts. **Pick a lane.** Either (a) lead with the 7-year discrimination number (10/11 union, 91%) and treat 12-month silence as a workload datum, or (b) keep the 12-month "zero misses" framing and label it `[workload, N=1 for discrimination]` every time it appears. The current text alternates and it reads inconsistent.

**The DI CWE set was widened to catch known misses.** CWE-444 (request smuggling) was added; CWE-287/289/306/345/693/863/1321 (auth-bypass widening) was added. Both changes catch CVEs that were known-exploited at the time of the widening. That is principled — auth-bypass-via-input-manipulation really is the same pattern as injection — and the page argues it correctly. But it is also goalpost-moving in disguise. The honest treatment: pre-register the widened set against held-out future CVEs and report a forward-validation result in 6 months. The page asserts this should happen ("Run it for 6 months. Track what it flags and what it skips") but doesn't yet hold itself to a frozen CWE set with a published cutover date. **Recommendation:** declare the CWE set frozen as of 2026-04-23 and start a public "events seen since freeze" counter. That is the only way to convert "this filter catches X" into "this filter caught X going forward."

**Hacker S+A is the least falsifiable component.** NP+DI is mechanical: same CVE, same CWE list, same NP package set → same trigger. Two analysts will agree. Hacker S+A is per-event tier S/A/B/C/D from a "trained operator" judgment. There is no inter-rater reliability stat reported. The page bills S+A as catching 9/11 vs. NP+DI raw's 5/11 — but a different operator might tier the same events at S+B or A+C. **The page should report (i) what fraction of the tier judgments would change if a second operator reviewed them, and (ii) whether the union claim holds under reasonable inter-rater variation.** The hacker-tier rounds in `analyst-reports/2026-04-25-hacker-ranking-v2.md` through `v9` exist — there is enough internal data to do an inter-rater sensitivity analysis. It hasn't been published.

**The model's "never worse than EPSS" claim is conditional.** The conclusion reads "with all three layers in place — floor-sweep, cadence, and threat-intel monitoring — the model is never worse than EPSS." That is true under the stated supplements. It is false if a Cat 3 estate runs strict version pinning, has no floor-sweep, and only acts on emergency triggers. The page acknowledges this in the EPSS marginal-cost caveat, but the headline claim doesn't carry the conditional. **Recommendation:** rewrite the conclusion to "the model + supplements is never worse than EPSS in Cat 1/Cat 2 estates with floor-sweep enabled; in Cat 3 estates the marginal cost rises and EPSS becomes a more useful standalone backstop." That is the honest version.

**The OS-layer "NP+DI = 0" claim is robust but the cleaning was post-hoc.** The 69 → ~18 component cleanup was driven by a manual sweep removing CVEs that NVD keyword-matched into the wrong component. That cleaning is correct but it is also the kind of analyst-degree-of-freedom that should be guarded against. **Recommendation:** publish the cleaned manifest and the keyword-noise filter as a script in `scripts/`, so the cleaning is reproducible. (The strategy efficiency table for 7-year is reproducible from `scripts/`; the OS cleanup should be the same.)

**"Burst pattern" is overinterpreted on small N.** Spring 5 NP+DI events: Apr 28, May 21, Sep 16, Apr 9, Apr 15. Calling that "silence punctuated by bursts" is generous — the only "burst" is the April 2026 Tomcat+Thymeleaf cluster, which the page also frames as a possible Mythos signal. The N=2 events in 6 days for Node.js and N=2 events in 5 days for Spring are real, but they're plausible under any Poisson process at λ ≈ 5/year. **Recommendation:** drop the "averages lie" framing. Show the dates, note the operational implication (you can run a regular cadence and absorb most of these even when they cluster), and don't claim a distributional property the data doesn't support.

**One more devil's-advocate point: the canonical 58-package manifest is one estate.** The 7-year backtest is on a Java enterprise stack. The 11 exploited events are dominated by Spring/Tomcat/Log4j/XStream/Jackson/ActiveMQ — Java's specific exploitation history. The model's discrimination on a Python-heavy or PHP-heavy estate is not measured. The cross-framework 12-month work covers Spring+Node+Django+Netty for *workload*, not for *discrimination on a 7-year horizon*. **Recommendation:** state explicitly that the 7-year discrimination result is on an enterprise Java manifest, and that Python/Node 7-year backtests are open work. Then put them on a roadmap.

### 1c. The kill-chain framing

The "app layer = IF, OS layer = HOW BAD" framing is good and operationally correct. The privesc-accumulation chart is useful. The cleaned numbers (~10-12 LPE-relevant after noise removal) make the case for monthly container refresh without overselling.

**One concern:** the model assumes LPE is the chaining vector. Container breakout (kernel/runtime escape) is arguably the worse chaining risk and is *not* in the OS manifest. The page mentions this in the "counter-argument worth considering" callout but doesn't commit to a position. The honest answer is that container-breakout CVEs should be tracked separately as a third tier — a kernel/runtime watch list — and the OS-layer LPE count is about lateral movement *within* the container, which is a different (and lesser) impact. **Recommendation:** carve out a "container-runtime watch list" as a fourth control alongside the app-layer NP+DI trigger, monthly OS refresh, and the existing exploit-watch-list. The runtime layer is the gap.

### 1d. External validation holds up

The five-source cross-check (EPSS / KEV / EDB / Nuclei / MSF) is well-structured. The summary table is fair: KEV / EDB / Nuclei / MSF "missed anything? No" — but with the caveat that KEV is product-biased (1 hit on the OS layer, 0 on app layer in 12 months means very little because libraries rarely make KEV in any 12-month window). The Nuclei + EDB + EPSS-89th-percentile triple-confirmation on CVE-2026-1207 (Django SQLi) is the single best independent validation in the dataset.

**The honest summary on validation:** KEV / MSF / EDB / Nuclei provide *weak* independent validation (low base rates, library-poor coverage) but they do not contradict the filter. EPSS provides *strong* validation in the form of the marginal-cost decomposition: NP+DI+DQ absorbs 87 of 90 events that EPSS ≥ 0.10 would have triggered on, 43 of 44 at EPSS ≥ 0.50. That is the validation the model can stand on. **The page should rank validation strength explicitly:** EPSS = strong, KEV/MSF/EDB/Nuclei = corroborating but low-power on this cohort.

---

## 2. Walkthrough restructuring recommendations

### 2a. Where the current walkthrough actually stands

The brief described the walkthrough as still proposing CVSS-tier patch SLAs in §9. That is no longer true. The current §9 is "Putting It Together: Operational Response by Estate Maturity" with Cat 1/2/3 framing — already reflecting the periodicity work. §3 is the model with both operationalizations. §4 is cross-framework + 7-year backtest. §7 is the kill chain. §8 is external validation. §9a is the WAF dividend.

**The walkthrough is not missing the periodicity content. It is structured around it.** What's left is reader-experience tuning, not insertion of major new sections.

### 2b. The narrative-arc problem

A first-time reader currently moves through:

1. Problem (volume + maturity profiles)
2. Observation (where exploits land — KEV vs NVD)
3. The model (NP+DI structure test + hacker test)
4. Cross-framework + 7-year validation
5. Why most criticals don't get exploited (survivorship)
6. Time-to-exploit compression
7. Kill chain (privesc accumulation)
8. External validation (EPSS / KEV / etc.)
9. Operational response (Cat 1/2/3, WAFs)
10. Reverse proxy myth
11. Watch list
12. Caveats

The trouble: the reader has been told the filter works (§4) before being told the prior reason it should work (§5 survivorship, §6 time-to-exploit). §5 and §6 belong *before* §3 as motivation, not after §4 as backfill. They are the "why we expected this to work" content; right now they read as "here are some additional things we know" after the reader has already accepted the validation.

§7 (kill chain) sits between validation and external validation. It belongs in the operational section because it justifies monthly container refresh — that's the operational lever the kill chain implies. Putting it in mid-validation breaks the validation arc.

§10 (reverse proxy myth) is a sidebar in the wrong place. It's a niche but interesting result; it should sit near §11 (watch list) or be folded into the supplements discussion.

### 2c. Recommended reordering (no new content, just new order)

The cleanest restructure preserves all current content and changes only the order:

**ACT 1 — The problem.**

- §1 Problem (current §1)
- §2 Where exploits actually land (current §2: KEV vs NVD, NP vs non-NP, libraries)
- **§3 Why most criticals don't get exploited** (current §5, moved up)
- **§4 Time-to-exploit compression** (current §6, moved up)

ACT 1 sets up the question: volume is huge, exploitation is rare, and when it happens it's fast. That motivates the need for a filter.

**ACT 2 — The model.**

- §5 The threat-based prioritization model (current §3: NP+DI + hacker discriminator)

**ACT 3 — Does it work?**

- §6 Cross-framework validation (current §4: 14-14-14, 7-year backtest, attacker test catches)
- §7 External validation (current §8: EPSS marginal cost, KEV/MSF/EDB/Nuclei, WAF defensibility)

**ACT 4 — How to operate it.**

- §8 Land & expand: the kill chain (current §7, moved here)
- §9 Operational response by estate maturity (current §9: Cat 1/2/3, WAF dividend)
- §10 Exploit watch list (current §11)
- §11 Reverse proxy myth (current §10, moved here as a supplements sidebar)
- §12 Caveats (current §12)

**Net change:** §5 and §6 move up; §7 moves down; §10 moves down. Eight sections of body content stay where they are and only have their numbers re-tied. This is a 90-minute editing pass, not a rewrite.

### 2d. Additional smaller surgery

- **§3 (current §3, "The Threat-Based Prioritization Model") is doing double duty.** It defines NP+DI, defines the hacker discriminator, defines the DI CWE set, and argues the falsifiability case. Split: §3a/b (NP+DI + DI CWE set) and §3d (hacker discriminator) are the two operationalizations; §3c (falsifiability) belongs as a sub-section within the model intro; §3e ("hidden cost of not filtering") is a motivation argument that belongs in ACT 1 alongside the problem statement, not in the model definition.
- **The "How to read this site" table at the top is good and should stay** — it is the only place a new reader is told what each page is for. Keep it. Add a "you have 60 seconds" row that points to the §1 TLDR card.
- **The §1 TLDR card has been rewritten more aggressively than the body text below it.** It now leads with "the threat-based prioritization model" but the body below still contains a few sentences phrased as if the model were a single filter. A grep for "the filter" should find ~15 callouts that should read "the model" in headline-position content; smaller mentions inside body paragraphs are fine where they refer to a specific operationalization (e.g. "the structure test fires").
- **§4f ("Real-World Case Study: Enterprise Java Portfolio")** is currently a sub-section of cross-framework validation. It carries the entire 7-year backtest. **Promote it.** Make it its own §6 in the new ordering, titled "Seven-year backtest: 11 exploited events on a real Java manifest." The 12-month cross-framework should be §6a (workload) and the 7-year should be §6b (discrimination). Right now both live inside one section with similar visual weight; the discrimination case is what carries the model and it should be visually separated.
- **The "zero-miss" framing** appears in 4-5 places in the walkthrough. Pick one. The honest version is: 7-year backtest catches 10/11 directly via union; 11/11 with supplements; 12-month synthetic-stack window has N=1 in-scope exploited and is therefore a workload measurement only. Headline that once. Remove the rest.
- **Section 7 (kill chain) figure** — the privesc accumulation chart is great but it currently uses the un-cleaned numbers (21 LPE) in the chart and the cleaned numbers (~10-12) in the prose. Pick one set and use it everywhere; if both are needed, plot both as overlaid lines.

### 2e. What to cut entirely

- The "April 2026 spike" sub-callout in §4 (current §4, also in periodicity.html §13) — it's an interesting hypothesis but it's an n=1 cluster speculation that distracts from the validation case in this section. It belongs in the Mythos / glasswing.html page, not here. Cross-link from the walkthrough.
- The **deserialization revisit** sub-section in periodicity.html is good content but it's argued in two places (walkthrough notes around §3b and periodicity §12). Pick one.

### 2f. What stays as-is

- §1 problem framing with the three operational profiles (active / infrequent / stale) — this is the entry-point sell and works.
- §2 stack-layer exploitation rates and the 3-6x lift result — observational backbone.
- The DI CWE table in §3b — it's the most concrete artifact in the document; readers cite it.
- The "Hidden cost of churn crowding out maturity climbs" argument (§3e) — should move to ACT 1 but the content is good.
- The Cat 1/2/3 framing in §9 — this is the most useful operational handoff in the document.
- The watch list (§11) — concrete, testable, and valuable.

### 2g. Should periodicity.html fold into the walkthrough?

**No.** Periodicity.html is the methodology page with full per-stack tables, full DI CWE rationale, all four heatmaps, the strategy efficiency table, the Tomcat 2017 worked example, and the per-event KEV/MSF/EDB flags. It is ~1,100 lines of receipts. Folding it into the walkthrough makes the walkthrough unreadable. **Cross-link aggressively.** Every walkthrough section that summarizes a periodicity result should link to the matching periodicity section.

What *can* fold in: the cross-framework comparison chart (already in walkthrough), the strategy-comparison stat block (already in walkthrough), and one summary heatmap if there's room. Everything else stays where it is.

---

## 3. Dashboard updates

### 3a. What the dashboard already has

The dashboard already includes: cross-framework chart, OS container chaining chart, EPSS chart, NP+DI hero stats with "10/11 union" framing, layer rates, OSV library distribution, HTTP-parsing lift, time-to-exploit, KEV by CWE family, ransomware-linked KEV, the three-tier model, server- and desktop-side watch lists, the thesis challenge table, and links to periodicity.html / cve-reference.html. That's a lot — the major periodicity findings *are* already represented.

### 3b. Concrete additions worth making

1. **Strategy efficiency table on the 7-year manifest.** The most decision-relevant table in periodicity.html is the strategy efficiency block (`#strategy-efficiency`): patch-all C+H / patch-criticals-only / NP+DI raw / NP+DI+DQ / hacker S+A / union, scored on patch events / raw triggers / exploits caught / effectiveness / overhead per exploit. **This belongs in the dashboard** — currently the dashboard shows only the 12-month cross-framework reduction, which is the workload story. The 7-year strategy efficiency is the discrimination story and it isn't on the dashboard.
2. **Strategy-comparison chart.** Bar chart, four bars per framework: All C/H, NP+DI raw, NP+DI+DQ, Hacker S+A. The periodicity page has this; mirror it to the dashboard.
3. **EPSS marginal cost stat.** Current dashboard shows the EPSS probability chart. Add a single-line stat block: "NP+DI+DQ absorbs 43 of 44 events that would have triggered on EPSS ≥ 0.50 alone." That is the most operator-friendly framing of the EPSS result and it isn't on the dashboard.
4. **Periodicity heatmap thumbnail.** One representative monthly heatmap (Spring or Django) as a thumbnail with a click-through to periodicity.html for the rest. Visually reinforces the burst-vs-cadence claim without bloating the dashboard.
5. **A "events since CWE-set freeze" counter.** Once the DI CWE set is frozen (see §1b recommendation), the dashboard should show: "Days since CWE-set freeze: N. NP+DI triggers since freeze: M. KEV hits among non-triggers since freeze: 0/X." That converts the dashboard from a static-data reflector to a forward-validation tracker. This is the single most defensive thing this project could add — every reviewer's concern about "you fit the filter to the data" is answered by a public running counter of post-freeze performance.

### 3c. What's now redundant or stale on the dashboard

- The "Median Time-to-Exploit (2021 → 2023): 251 days → 11 days" hero KPI is a 2024-vintage stat. It's still valid as motivation but it was the centerpiece of the walkthrough's pre-periodicity framing. **Demote it.** Move it from one of the two top-row hero KPIs to the supporting-stats row. Replace one of the hero slots with the 7-year discrimination stat: "10/11 actually-exploited events caught directly (union of NP+DI+DQ ∪ Hacker S+A)." That is the load-bearing claim of the project now.
- **The KEV-by-CWE-family chart and ransomware-by-stack-layer chart** are both vestigial. They're observational results from the original "where exploits land" analysis. They don't connect to any operational decision the dashboard supports. **Either** add a one-line callout that ties each to a specific filter decision (e.g. "ransomware operators concentrate on the same NP+DI surface, see X") **or** move them to a "context / supporting analysis" lower section.
- **The "Firmware/Hardware / Linux Kernel Local / Consumer IoT / Niche Products" thesis-blind-spot section** is a hangover from the original thesis-challenge framing. It's still right but it sits awkwardly next to the operational triage content. Move it to a "what this filter doesn't cover" section near the bottom — readers using the dashboard for triage decisions don't need it on the way in.

### 3d. Dashboard architecture suggestion

The dashboard has accumulated multiple sections without a clear hierarchy. Suggested top-down ordering:

1. Hero KPIs: 7-year discrimination (10/11 caught), days since CWE freeze (when implemented), time-to-exploit (demoted)
2. The model: cross-framework chart + 7-year strategy efficiency table + EPSS marginal-cost stat
3. The kill chain: container chaining chart + monthly cadence reduction stat
4. Watch list (server-side + desktop)
5. Supporting analysis: layer rates, OSV libraries, HTTP-parsing lift, time-to-exploit detail
6. Thesis blind spots
7. Methodology footer + links to periodicity / cve-reference / glasswing / build-mechanics

Right now the order is more like: hero, model, layer rates, libraries, parsing lift, time-to-exploit, blind spots, CWE families, ransomware, three-tier model, watch list, thesis-challenge. The grouping should pull the operational decision-relevant content above the observational supporting content.

---

## 4. Cross-page architecture

### 4a. The four primary pages

- **`docs/index.html` (walkthrough)** — narrative front door. ~30-min read. Tells the story: problem → observation → model → validation → operations → caveats. Links into the other three pages for receipts.
- **`docs/dashboard.html`** — live data + operational view. Refreshes nightly via the kev-analysis-refresh agent. The "look at the data" page.
- **`docs/periodicity.html`** — methodology / receipts page. Per-stack manifests, per-CWE rationale, 7-year backtest, external validation in detail, monthly heatmaps. The "look at the work" page.
- **`docs/cve-reference.html`** — per-CVE audit trail. Sortable, filterable. The "look at every classification" page.

Plus secondary: `glasswing.html` (Mythos page), `build-mechanics.html` (operational model + Cat 1/2/3 + WAFs), `evergreen.html` / `osv-exploitation.html` / `foss-sub7.html` (scratch analysis pages). These are correctly secondary today — they shouldn't graduate to primary nav without a deliberate decision.

### 4b. The "front door" experience

A new reader landing on funwithscience.net/KEV-analysis/ should:

1. Hit `index.html` first. It is the canonical entry point and currently has a "How to read this site" reading-time table at the top that does its job.
2. From the TLDR/§1, branch by intent: 5-min reader stays; 30-min reader keeps going; "verify the work" reader goes to periodicity + cve-reference; "see the data live" reader goes to dashboard; "Mythos angle" reader goes to glasswing.

The reading-time table is the right pattern. Two small fixes:

- **Add a "60 seconds" row** linking to the TLDR card. The 5-min row is already a soft jump to §3; a dedicated 60-second entry point lowers the bounce-bar.
- **The "verify the work" row** currently lists periodicity + cve-reference. Add `data/CLASSIFIER.md` for the layer classifier and `tests/run.sh` mention for the test suite. People who want to verify want to know there are tests.

### 4c. Navigation consistency

All four primary pages have a header nav. They should expose the same set, in the same order, on every page:

`Walkthrough` · `Dashboard` · `Periodicity` · `CVE Reference` · `Mythos` · `Operational Model`

The current nav state varies slightly across pages (e.g. some pages list `Mythos` as the participant intel page, others as `Glasswing`). Standardize on `Mythos` (which is the public-facing Anthropic name for the program) and make sure every page's nav has the full set in the same order. This is plumbing — should be a 30-minute edit across all pages.

### 4d. What should not change

- **`periodicity.html` stays separate.** It's the methodology depth-charge and folding it into the walkthrough makes the walkthrough unreadable.
- **`cve-reference.html` stays separate.** It's the audit trail; readers go there to argue with classifications, not to learn the methodology.
- **`glasswing.html` stays separate.** It's clearly labeled as speculative intelligence and shouldn't bleed into the data dashboard.

### 4e. What might consolidate later

- **`evergreen.html`, `osv-exploitation.html`, `foss-sub7.html`, `build-manifesto.html`** are scratch pages. They are valuable for the analyst and contributor audience but a new reader will trip on the proliferating side-doors. Consider a "scratch / open work" landing page that lists them with one-line summaries; primary nav points to that landing page rather than each scratch page individually.

---

## 5. Daily scan addendum (2026-04-30 → 2026-05-01)

### 5a. KEV / new CVE activity

Per `kev-tracking.json` and the rolling notes in `config.json:exploit_intelligence`, no maturity changes for the 18 watch list CVEs since the 2026-04-29 sweep:

- **CVE-2026-39987 (Marimo, weaponized)** — ITW exploitation continues per Sysdig threat intel. No change.
- **CVE-2026-20180/-20186/-20147 (Cisco ISE)** — no public PoC indexed. Confirmed Codex (OpenAI), not Mythos. Tracked under `glasswing_targets.ai_attributed_non_mythos_cves`.
- **CVE-2026-5194 (wolfSSL)** — Claude-credited, no public PoC.
- **Spring AI cluster (-40966 / -40967 / -40978 / -40979 / -40980)** — Apr-27/-28 disclosures, no public PoC. Worth watching: spring-ai is in the Spring ecosystem, NP-adjacent (it sits behind HTTP endpoints in deployed apps), and these are fresh enough that triage classification hasn't been published.
- **CVE-2024-1708 (ConnectWise ScreenConnect)** — added to KEV 2026-04-29. NP+DI candidate (path traversal-class). Not on the current watch list. Worth a one-line addition to confirm or deprioritize.

### 5b. Glasswing / Mythos news

- No participant-attributed CVE additions in the last 24-48 hours beyond what's already documented.
- Spring AI cluster — Spring/Pivotal is **not** a Glasswing participant, so the cluster doesn't qualify under the participant-self-scan criteria. Note for the analyst: Spring is owned by Broadcom (which *is* a participant via the VMware acquisition). If the Spring AI fixes carry no third-party credit and follow the automated-scan-bug pattern, that's a probable-participant signal worth flagging on next sweep. Not enough yet to add to `probable_participant_cves`.
- The probable-participant table remains empty per the 2026-04-29 calibration (Cisco-ISE/Webex moved to ai_attributed_non_mythos_cves once Cisco directly confirmed Codex).

### 5c. Glasswing participant cross-check

Ran new CVE candidates from the last 24h against the participants list (`AWS`, `Anthropic`, `Apple`, `Broadcom`, `Cisco`, `CrowdStrike`, `Google`, `Intel`, `JPMorganChase`, `Linux Foundation`, `Microsoft`, `Nvidia`, `Palo Alto Networks`):

- **Spring AI cluster** — Pivotal/Spring → Broadcom (participant via VMware). Tentative participant-vendor. Other criteria (HTTP-adjacent, no third-party credit, automated-scan pattern): partially met. **Add to watch list as suspected; do not yet add to probable_participant_cves.**
- **CVE-2024-1708 ConnectWise** — not a participant vendor.
- **CVE-2026-39987 Marimo** — not a participant vendor.

No additions to `glasswing_targets.probable_participant_cves` from this scan.

### 5d. One small item for tomorrow's refresh agent

The Spring AI cluster (CVE-2026-40966/-40967/-40978/-40979/-40980) is fresh enough that NP/DI classification hasn't been done. If the refresh agent ingests these, a quick NP+DI pass would help — they're spring-ai (NP-adjacent: HTTP endpoint exposed) and a CWE check would close the loop on whether the model would have fired on disclosure day.

---

## Closing note

The periodicity work moves the project from "we observed network parsers get exploited more" to "we have a triage policy that catches 10 of 11 exploited events on a 7-year backtest with one-third the patch overhead of patch-all-criticals." The walkthrough has already absorbed this story; what's left is a re-ordering pass to make the narrative arc reader-friendly and a tightening pass to remove the "zero-miss" overclaim. The dashboard has the major content but is missing the 7-year strategy efficiency table — that's the single biggest dashboard gap right now. The four-page architecture (walkthrough / dashboard / periodicity / cve-reference) is sound and should not consolidate.

The single most useful next step, beyond the editing, is **freezing the DI CWE set with a published cutover date and starting a "since-freeze" counter on the dashboard.** Every reviewer concern about hindsight CWE selection is answered by forward validation; the project has the infrastructure to do it (refresh agent, daily scan, watch list), and a public counter would convert the strongest current critique into the strongest future evidence.
