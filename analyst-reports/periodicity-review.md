# Analyst Review: Periodicity Analysis Integration & Walkthrough Restructuring

**Date:** 2026-04-21
**Reviewer:** KEV analyst agent
**Scope:** Evaluate `docs/periodicity.html` + `docs/cve-reference.html`, then recommend restructuring for `docs/index.html` and updates to `docs/dashboard.html`.

---

## TL;DR

The periodicity analysis is the strongest single piece of work in this repo, and the walkthrough does not currently reflect that. The NP+DI filter turns the project's thesis from observational ("network parsers get exploited more") into prescriptive ("here is the exact filter that tells you when to rebuild, here is twelve months of validation, here is what it costs you when it's wrong"). The methodology is largely sound, the zero-miss finding is real but should be claimed more carefully (the KEV baseline is thin), and the three-tier model is the operational payoff that the current index.html is missing.

My bottom line recommendations:

1. **Keep periodicity.html as a separate deep-dive page, but promote the three-tier model and zero-miss finding to the front of index.html and demote most of the current Section 9 (Patch SLA Framework).** The current 72h/7d/30d framework predates the periodicity work and is inconsistent with it — the periodicity data explicitly argues that "CVSS triages on severity" is the wrong axis.
2. **Index.html needs structural surgery, not edits.** The current narrative arc is "here is the hypothesis → here are scattered pieces of evidence → here are recommendations." The new arc should be "here is the observational case → here is the prescriptive filter → here is cross-framework validation → here is external validation → here is the operational model." Mythos and Watch List are secondary concerns that should follow, not interleave with, the core story.
3. **Dashboard needs a new section at the top for the NP+DI filter** (cross-framework bar chart, zero-miss stat, link to periodicity + reference). It doesn't need to be dismantled — it's currently a reasonable data exhibit page — but it should visibly lead with the periodicity result.
4. **cve-reference.html stays exactly where it is.** It's the audit trail for periodicity.html and works fine as a linked-from-main-analysis reference. No restructuring needed.
5. **"Front door" should be index.html, but the top-of-page TL;DR must direct technical readers to periodicity.html immediately.** Right now a sharp reader would bounce off index.html before discovering the better page.

---

## 1. Assessment of the Periodicity Analysis

### 1.1 Methodology — largely sound, with two caveats

The NP+DI filter construction is straightforward and defensible:
- **NP** is a judgment call on which dependencies parse untrusted network input. The manifests are published, the classifications are in cve-reference.html, and a skeptical reader can re-draw the line. That's the right way to handle a subjective step.
- **DI** is a concrete CWE set (78, 77, 22, 23, 36, 94, 95, 89, 918, 917, 1336, 116, 74, 75, 113, 93, 611, 91, 90, 79). The set is defensible — it's the canonical injection family — but it's worth stating what's deliberately excluded (memory corruption, DoS, info leak) and why. The page does this well.

**Two methodology caveats the author acknowledges but that should be pulled forward:**

- **CWE-20 is ambiguous.** Several "not DI" classifications depend on whether CWE-20 events are treated as input validation (no) or injection (yes). The page notes this. Good — but in the walkthrough version, this should be stated up front because it's the single biggest lever a critic could pull on.
- **OSV severity coverage is ~74%.** The other 26% of advisories lack parseable severity. Some C/H events are almost certainly missing from the backtest. The page concedes this but glosses it; in the walkthrough this should be an explicit "the numerator is probably 5-10% undercounted, which cuts against the filter's apparent effectiveness" caveat. Being conservative about your own win strengthens the case.

### 1.2 Cross-framework validation — convincing, with one concern

The result that three independent ecosystems (Maven/Spring, npm/Node, PyPI/Django) all hit **14 distinct C/H dates in 12 months** is the single most interesting structural finding. It's almost too clean — 14-14-14 — and deserves a sentence explaining why it's not cherry-picking. The manifests were chosen independently (they weren't back-fit to produce 14), and the convergence is a denominator effect: once you hit a certain dependency count, the C/H treadmill converges on a monthly-ish cadence regardless of which ecosystem you're in. That's actually a strong point and should be made explicit.

The reduction percentages (85% / 86% / 71%) and silence windows (189 / 311 / 140 days) are the real story. **Node.js's 311-day silence is the most impressive single number in the entire analysis**, and it gets buried in the table. In the walkthrough version this should be a hero-stat call-out.

**One concern:** Django is labeled the "honest weak case" in a dedicated section, which is good devil's-advocate framing, but the 4-events-in-12-months result is still operationally dominant over "rebuild on every C/H" (14 events). The framing could usefully flip: Django is the *worst case the filter handles*, and it still delivers quarterly cadence instead of biweekly. That's a stronger claim than "it's weak on Django." The current framing undersells the result.

### 1.3 OS chaining / kill chain framing — correct and important

This is the part of the analysis that elevates it from "clever filter" to "operational model." The two-axis framing —
- **App layer = IF** (initial access via NP+DI → determines whether you get breached)
- **OS layer = HOW BAD** (local privesc availability → determines blast radius)

— is genuinely useful and, as far as I can tell, not a framing I've seen elsewhere in the patching-cadence literature. The specific numbers (11 privesc CVEs at 189d, 21 at 353d, monthly refresh caps at 5) should be treated as approximate (the page admits systemd keyword noise inflates counts) but the *shape* is robust.

**One place to push back:** The analysis treats local privesc as the main chaining risk. Container breakout (escaping to the host via runc/containerd/kernel bugs) is arguably the bigger post-exploitation concern, and those CVEs are not captured in the Amazon Linux 2023 manifest. The page concedes this in the counter-argument card, which is good, but in the walkthrough we should lead with the concession: "this model addresses within-container blast radius, not full breakout. Breakout requires a separate analysis we haven't done." That's an honest statement of scope, not a weakness.

### 1.4 External validation & "zero-miss" — real, but claim it carefully

**The finding as stated:** Across 113 non-trigger CVEs in 12 months, zero appeared in KEV, one in ExploitDB (sqlite heap overflow, non-trigger, local access only), one Metasploit module (zlib/MongoDB, different deployment context). EPSS shows triggers score 3.3x higher (mean) / 2.5x higher (median). Django SQLi (a trigger) is converging across EPSS top-scorer + ExploitDB + Nuclei template.

**What's strong about this:** The methodology of testing both directions (do triggers correlate with exploitation evidence AND did non-triggers accumulate evidence) is the right structure. The explicit framing of "we want zero misses, not exact right" is the right epistemic posture. The EPSS circularity caveat (EPSS uses the same CWE features our filter uses) is acknowledged honestly.

**Where it needs to be tempered:**

- **KEV is very thin for library-level CVEs.** Only ~3.8% of KEV entries are libraries, and none of our 129 CVEs were in KEV to begin with — most of the dataset is 2025-2026 and the KEV pipeline lags 4-8 weeks. The zero-miss claim isn't "these weren't exploited" — it's "these haven't yet accumulated public exploitation evidence in a 12-month window that is still open for most of the dataset." That's still meaningful, but it's weaker than the callout language implies ("the filter hasn't been wrong yet").
- **ExploitDB coverage is biased toward products and toward older CVEs.** Library-level CVEs in the 2025-2026 era with no ExploitDB entry is the *default*, not a strong signal. The page concedes this. But the walkthrough should say so plainly: absence of ExploitDB entry is a weak signal, especially for recent library-level bugs.
- **The leading-indicator framing is aspirational.** The claim that the filter may be finding CVEs *before* the exploitation ecosystem catches up is plausible but currently supported by exactly one data point (CVE-2026-1207, Django SQLi, converging across EPSS/ExploitDB/Nuclei). The page hedges appropriately ("so far, so good"). The walkthrough version should match that restraint.

**Net:** The zero-miss result is the most commercially attractive claim in the analysis, and it's correct *as measured*. The risk is that "twelve months of zero misses in a dataset with known coverage limitations" gets quoted as "the filter has never been wrong," which is a stronger claim than the evidence supports.

### 1.5 Devil's-advocate: what could undermine these conclusions?

Things I would press on if I were hostile to this analysis:

1. **Selection effects in manifest choice.** Three manifests, each ~40-50 deps, each hand-picked to be "representative" of their ecosystem. Were manifests chosen in a way that happened to avoid high-churn NP dependencies? Spring Boot has no jackson-databind deserialization event in 12 months — that's unusual. If you had picked a different 12-month window (say, the Log4Shell year), the filter would have looked much more expensive to operate. The 12-month snapshot is favorable in part because the gadget-chain CVE factory happens to be in a quiet period. The page acknowledges this in "Deserialization Question (Revisited)" but the framing is "the ecosystem has quieted" rather than "we got lucky with our window." Honest framing cuts both ways.
2. **14-14-14 convergence may be dependency-count-driven, not ecosystem-intrinsic.** If you reduced each manifest to 10 deps, the NP+DI frequency would be much lower and the "all C/H" frequency would be much lower too, possibly preserving the reduction ratio. That's a *strength*, not a weakness, but it means the 14-events-a-year number is not fundamental — it's a manifest-size artifact. Worth stating.
3. **Transitive dependencies aren't modeled.** The manifest is direct deps only. A real Spring Boot app pulls 200+ JARs. The full tree would push "all C/H" even higher (more noise) and probably grow NP+DI less than proportionally (more signal) — so the reduction % likely understates the real benefit. But a skeptic could argue the opposite: maybe transitive deps introduce unmodeled NP+DI events the direct-dep analysis misses. Worth a sentence.
4. **The Oct 27 Tomcat path traversal trigger is close to the end of the 12-month window.** If the window had ended one week earlier, Spring Boot would show 5 events of 14 all-C/H with 1 NP+DI event — an even stronger-looking reduction. And if it had ended one week later after a quiet April, the Spring numbers would look worse. The 85% figure is window-sensitive. This is a known stability-of-result concern and the analysis would benefit from a sensitivity analysis (e.g., "what if we shift the window ±1 month?").
5. **The filter treats all DI CWEs as equal weight.** CWE-79 (XSS) in a template engine is classified as DI and triggers a rebuild. But most XSS bugs are not RCE-equivalent; they're session-theft-class. The current filter doesn't distinguish RCE-path DI from non-RCE-path DI. Arguably the filter should be split into RCE-trigger vs XSS/XXE-trigger tiers. This is a refinement, not a fatal flaw, but a reader could legitimately ask why XSS triggers emergency rebuild.
6. **The "monthly container refresh" recommendation in the three-tier model is not directly tested by the data.** The data shows privesc CVEs accumulate; the recommendation of "monthly" is inferred from the observation that monthly caps worst-case at 5 CVEs. But the data doesn't test "is monthly actually the optimal cadence or is it somewhere between weekly and quarterly?" The page says "going to bi-weekly only saves one more CVE" and concludes monthly is efficient, but there's no cost function (refresh cost × blast-radius reduction) being optimized. This should be stated: the monthly recommendation is a heuristic supported by the data, not a provably optimal cadence.

**None of these are fatal.** They are the sharpenings the analysis needs before it can survive hostile review. The core result — that NP+DI produces 71-86% reduction across ecosystems with zero observed misses — is robust to all six concerns.

---

## 2. Walkthrough Restructuring Recommendations

### 2.1 The core problem with index.html as it stands

The current walkthrough is structured as it was originally conceived: an observational analysis of why HTTP-parsing-adjacent components are exploited more. Every section serves that thesis. The periodicity analysis is a superset of that thesis — it makes the observation, then operationalizes it. Bolting periodicity content onto the current structure will produce a confusing document that reads like two analyses stapled together.

Specifically:

- **Section 9 (Patch SLA Framework) is now internally inconsistent with the project's own work.** It proposes 72h/7d/30d SLAs based on (a) "CVE in KEV," (b) "network-parsing C/H not in KEV," (c) "all other C/H." The periodicity analysis argues that (b) is too broad — most network-parsing C/H are DoS, info leak, or non-DI, and emergency-rebuilding on all of them is exactly the noise the NP+DI filter was designed to eliminate. Either the framework in Section 9 needs to be rewritten to match the NP+DI model, or it needs to be framed as "an earlier, coarser version that the periodicity analysis refines."
- **Section 10 (Mythos Detector) and Section 11 (Watch List) are legitimate ongoing work but they interrupt the structural argument.** A reader who comes to this document looking for "how do we manage our patching queue" wants the periodicity model first. Mythos is a secondary question: "will the CVE firehose grow?" It should come after the prescriptive model, not in the middle.
- **Section 5 (Why Most Criticals Don't Get Exploited) and Section 8 (CWE & Ransomware) are supporting evidence for the hypothesis but take up a lot of reading time.** They should be trimmed and merged.

### 2.2 Proposed new section outline

Here's a recommended structure. New or heavily-changed sections marked [NEW] or [REWRITE]; existing sections marked [KEEP/TRIM/MERGE].

```
1. The Hypothesis                                       [TRIM — shorten to 2-3 paragraphs]
2. Methodology                                          [KEEP]
3. The Observational Case: Network Parsers as Predictor [MERGE of current 3, 4]
   3a. Stack layer exploitation rates
   3b. Network-parsing vs non-parsing across CVSS
   3c. Libraries: why NVD undercounts, OSV is the real denominator
4. Why Most Criticals Don't Get Exploited               [TRIM current 5 — shorter]
5. Time-to-Exploit Compression                          [KEEP current 6]
6. From Observation to Filter: NP+DI                    [NEW — the pivot]
   6a. The two criteria: Network Parser + Direct Injection
   6b. Why the filter is testable (and falsifiable)
7. Cross-Framework Validation                           [NEW — lift from periodicity.html]
   7a. Three stacks, 14-14-14 convergence
   7b. Reduction rates and silence windows
   7c. Burst pattern vs steady drip
   7d. Django: the honest hardest case
8. Kill Chain: App Layer IF, OS Layer HOW BAD           [NEW — lift OS chaining content]
   8a. OS layer produces zero NP+DI triggers in 12 months
   8b. Privesc accumulation over time
   8c. Monthly container refresh math
9. External Validation: The Zero-Miss Window            [NEW — lift external-validation section]
   9a. EPSS correlation (with circularity caveat)
   9b. KEV / ExploitDB / Nuclei / Metasploit cross-check
   9c. What zero-miss does and doesn't claim
10. The Three-Tier Patching Model                       [REWRITE of current 9]
    10a. Tier 1: NP+DI emergency (2-4x/year)
    10b. Tier 2: Monthly container refresh (blast radius)
    10c. Tier 3: Ride the release cycle (everything else)
    10d. What this replaces: the CVSS-tier SLA approach
11. The Reverse Proxy Myth                              [MOVE — from current 4 to here as a defense-in-depth companion]
12. Mythos Detector                                     [KEEP current 10, but demote — it's context, not the core]
13. Exploit Watch List                                  [KEEP current 11]
14. Finance Sector KEV Blind Spots                      [MOVE / TRIM — current 7, demote to appendix or cut]
15. CWE Families & Ransomware                           [TRIM or FOLD into Section 3 — current 8]
16. Caveats & Limitations                               [KEEP current 12, append periodicity caveats]
```

### 2.3 What to cut or cut back

- **Section 7 (Finance Sector Blind Spots) is interesting but off-thesis.** It's about KEV curation bias, not about patching cadence or the NP+DI filter. I would move it to an appendix or cut it entirely from index.html and keep it as a standalone post or move it to dashboard.html as a collapsed expandable. Current state: it's a speed bump in the middle of the narrative.
- **Section 8 (CWE Families & Ransomware) duplicates evidence already shown in Section 3.** Memory corruption (298) and injection (235) dominating KEV is exactly the "network-parsing attack surface" story. The ransomware angle (20% of KEV) is interesting but tangential. Fold the core numbers into Section 3 and cut the separate section.
- **Section 5 (Why Most Criticals Don't Get Exploited) has six sub-patterns.** Firmware, kernel-local, IoT, non-Western ecosystems, memory corruption complexity, niche products. Trim to 3-4 sentences per pattern. The current version reads like a taxonomy defense rather than a payoff.
- **Section 9 (current Patch SLA Framework) should be cut, not rewritten in place.** Its replacement is Section 10 in the new outline. Preserve the three-tier structure (emergency / urgent / standard → emergency / regular / ride-the-cycle) but abandon the SLA-by-days framing (72h / 7d / 30d) because the periodicity data argues the right framing is by filter outcome, not by time window.

### 2.4 What to add

Four things that don't currently exist in the walkthrough at all:

1. **A TL;DR box at the very top that leads with the three-tier model and the zero-miss number.** The current TL;DR bullets lead with "3-6× exploitation lift for network parsers," which is the observational finding. It should lead with "we tested a sharper filter across 3 ecosystems and it cut emergency rebuilds by 71-86% with zero misses in 12 months" — that's the newsworthy claim.
2. **Sidebar CTA above the fold: "Jump to the filter" / "See every CVE classified."** Link directly to Section 6 (NP+DI) of the new structure and to cve-reference.html. Give an impatient reader a fast path.
3. **A sensitivity/stability-of-result paragraph.** What happens if you move the 12-month window? What happens if you widen the CWE set? What happens if you reclassify one component as non-NP? This is the "how confident should you be" section and it's completely missing. A 3-4 sentence version with one chart would cover it.
4. **A cost model for the three tiers.** The current analysis shows the *benefit* of the filter (fewer emergency rebuilds, less privesc exposure). It doesn't quantify the *cost* of the non-trigger CVEs — presumably none of them will bite you, but what's the worst that could happen in the window between filter-skip and next monthly release? This is where the skeptic's question lives.

### 2.5 Whether periodicity.html should be folded into index.html

**Recommendation: keep them separate.** Three reasons:

1. **Audience split.** index.html is the narrative walkthrough for a reader who wants the full argument. periodicity.html is the technical report for a reader who is already sold and wants the numbers. Merging them would force one document to serve both, and the compromise would weaken both.
2. **Layout.** periodicity.html uses a dark data-report aesthetic that matches dashboard.html. index.html is a light reading aesthetic. Folding in periodicity.html would either require a big visual redesign of index.html or would produce an ugly hybrid.
3. **Update cadence.** periodicity.html is a static snapshot (Apr 2025 - Apr 2026). index.html is maintained / rewritten as the thesis evolves. Keeping them separate means the static snapshot doesn't need to keep pace with narrative edits.

**But:** index.html should summarize the periodicity findings *in its own words*, not just link out. Sections 7, 8, 9 in the new outline should contain the numbers, the charts, and the argument — the link to periodicity.html is for the full methodology and the CVE-level detail. Think "executive briefing → technical appendix," not "executive briefing → click here to find out more."

---

## 3. Dashboard Updates

The dashboard is lighter surgery. It's already data-focused, which is the right register for the periodicity findings.

### 3.1 Add a new section at the top: "The NP+DI Filter"

Insert above the current "Exploitation Rate by Stack Layer" section. Contents:

- Hero stats: `14 all-C/H dates → 2-4 NP+DI dates` · `71-86% reduction` · `0 misses in 12 months` · `Full classification →`
- The `crossFrameworkChart` (bar of 14-14-14 vs 2-2-4) lifted directly from periodicity.html
- The `chainingChart` (privesc accumulation + Spring triggers) lifted directly
- Prominent links to periodicity.html and cve-reference.html

This makes the periodicity result visible on the dashboard without redoing the whole page.

### 3.2 Replace current "Recommended Patch SLA Framework" with "Three-Tier Patching Model"

The existing three-card section (Emergency 72h / Urgent 7d / Standard 30d) should be replaced with:

- **Tier 1 — Emergency:** NP+DI in app layer (`14 events/year → 2-4 after filter`)
- **Tier 2 — Regular cadence:** Monthly container refresh (`caps blast radius at 5 privesc CVEs vs 21`)
- **Tier 3 — Ride the release cycle:** Everything else (`0 of 113 non-triggers in KEV`)

Same three-card layout, different content. This fixes the internal inconsistency between the dashboard's current SLA framework and the periodicity findings.

### 3.3 Add EPSS validation as a new small card

The `epssChart` from periodicity.html should go somewhere on the dashboard — probably next to the existing CWE chart or in a new "External Validation" row. It's the strongest single piece of quantitative corroboration and isn't currently visible on the dashboard at all.

### 3.4 What's redundant or should move

- **The "Recommended Patch SLA Framework" section needs replacing (see 3.2).**
- **The "Finance Sector KEV Blind Spots" expandable can stay — it's collapsed by default and doesn't take up real estate.** But it's increasingly orthogonal to the main narrative.
- **The "Why Most Criticals Don't Get Exploited" grid-of-cards is duplicative with index.html Section 4/5.** Consider collapsing it behind an expandable as well.

### 3.5 Navigation / header

The dashboard currently links to index.html in the header. It should also prominently link to periodicity.html and cve-reference.html. Propose a small pill-button nav at the top: `Walkthrough · Dashboard (current) · Periodicity Analysis · CVE Reference`.

---

## 4. Cross-Page Architecture

Four pages, four roles:

| Page | Role | Audience | Update frequency |
|---|---|---|---|
| **index.html** | Narrative walkthrough. The argument, in prose. | Technical readers new to the thesis. | Rewritten as thesis evolves. |
| **dashboard.html** | Live data exhibits. Charts, tables, watch list. | Readers who want the numbers, not the argument. | Daily (refresh agent). |
| **periodicity.html** | Deep-dive technical report on NP+DI filter. | Readers who want methodology + full validation. | Static snapshot. |
| **cve-reference.html** | CVE-by-CVE classification audit trail. | Reviewers verifying the filter. | Static snapshot. |

**Navigation recommendation:**

Every page should have a top-of-page nav with all four links and a clear "you are here" indicator. The current state (index.html links to dashboard; dashboard links back; periodicity links to cve-reference; cve-reference links back to periodicity; no cross-links between the observational pair and the periodicity pair) is broken.

**"Front door" experience for a new reader:**

The default landing page (GitHub Pages root) currently serves index.html. That's correct — it's the narrative. But the current index.html does not make the periodicity work discoverable. A new reader today would:
1. Land on index.html.
2. Read the TL;DR (observational findings).
3. Scroll through 12 sections of observational argument.
4. Maybe click through to dashboard.html at the end.
5. Never find periodicity.html or cve-reference.html unless they read the footer carefully.

That's the core problem. Fix by (a) adding prominent CTAs to periodicity.html above the fold on index.html, (b) replacing the current Section 9 with a pointer to the three-tier model that lives in the new Section 10, and (c) adding the nav bar described above.

---

## 5. Specific Section-by-Section Notes for index.html

Line-level recommendations for the sections I read carefully:

- **Lead paragraph (line 126):** "1,568 confirmed exploits against 23,501 critical/high CVEs ... single structural question: does this component parse untrusted network traffic?" This is the old observational frame. Replace with: "We took that observation and built a testable filter. Across 12 months of real CVEs in three ecosystems, the filter reduced emergency rebuilds by 71-86% without missing a single exploit." Observational → prescriptive.
- **TL;DR box (lines 129-138):** Replace bullet 1 with the periodicity result. Keep bullet 3 (time-to-exploit). Keep bullet 4 (6.7% exploitation). Cut or compress bullets 2 and 5 — they're supporting detail, not headlines.
- **Section 1 (Hypothesis):** The opening paragraph is good. The long discussion of OSV vs NVD undercounting is important but doesn't need to be in Section 1 — move to Section 3b.
- **Section 2 (Methodology):** Needs one paragraph added about the periodicity backtest — what manifests, what window, what external sources. Frame: "Sections 3-5 rely on the KEV/NVD join described above. Sections 7-9 use a separate 12-month OSV backtest against three sample application manifests; details in periodicity.html."
- **Section 3 (Stack Layer):** Fine as is. Maybe trim libraries-deep-dive to tighten.
- **Section 4 (HTTP-Parsing / Network Parsers):** This is currently the strongest section of the walkthrough and it's the observational case. Keep it mostly as is, but add a closing paragraph that says "The rest of this document answers: given that network parsers are the exploitation signal, can you build a patching filter around that signal? See Section 6."
- **Section 5 (Survivorship / Why Most Don't Get Exploited):** Trim, per 2.3 above. The six patterns should be bullets, not paragraphs.
- **Section 6 (Time-to-Exploit):** Good as is. The 3-day P25 is a killer statistic and should probably get a hero-stat treatment in the dashboard too.
- **Section 7 (Finance):** Cut from main narrative, move to appendix or dashboard expandable.
- **Section 8 (CWE & Ransomware):** Fold the 20% ransomware number into Section 4. Cut the rest.
- **Section 9 (Patch SLA):** This is the biggest cut. The 72h/7d/30d framework predates the periodicity work and is inconsistent with it. Replace with the three-tier model (Section 10 in the new outline).
- **Section 10 (Mythos):** Keep but demote. The 40-CVE count, the Cisco cluster, the probable-participant table — all good. But this should come *after* the core patching argument, not interleaved with it. Frame: "A separate question: is the volume of incoming CVEs about to change? Here's our ongoing tracking."
- **Section 11 (Watch List):** Keep. The watch list is the daily operational output of the analyst agent and is the right place for it.
- **Section 12 (Caveats):** Add the periodicity-specific caveats: OSV coverage, CWE-20 ambiguity, manifest selection, window sensitivity, 12-month horizon for zero-miss claim.

---

## 6. Daily Scan Addendum

A quick scan of the 24-hour window since the 2026-04-21 morning report. Per the analyst-reports/2026-04-21.md and rolling.md already in the repo:

- **KEV:** No new entries since the 8-entry batch on 2026-04-20 (all HTTP-parsing-adjacent — Cisco SD-WAN Manager ×3, Kentico Xperience, PaperCut NG/MF, Zimbra, Quest KACE SMA, JetBrains TeamCity). April KEV total: 22.
- **Glasswing / Mythos:** No new direct-attribution CVEs in the 24h window. Count holds at 40 / 3 Claude-in-credit-line / 0 in KEV. The 46-day Cisco SD-WAN exploitation-to-KEV gap established yesterday is the relevant structural finding — it pushes the realistic Mythos-exploitation falsification window out to late May or early June 2026.
- **Cross-check against participant list:** Today's KEV batch's Cisco SD-WAN Manager cluster disqualifies for the probable-self-scan table because active exploitation was confirmed before disclosure (2026-03-05). The config.json `probable_participant_cves` list is unchanged. No new probable-participant candidates in the 24h NVD pull.
- **OpenClaw cluster:** The 12+ CVE OpenClaw cluster flagged yesterday (CVE-2026-41329 sandbox bypass CVSS 9.9, CVE-2026-41296 TOCTOU, CVE-2026-41303 authz bypass) continues the AI-stack-products-as-target pattern. Not adding to the watch list; Marimo and n8n already represent the class.
- **Oracle April 2026 CPU:** 483 new security patches shipped 2026-04-21. Expect a back-population pulse in NVD in May.
- **Nothing contradicts or refines the periodicity review above.** The day's data is consistent with the broader pattern the periodicity analysis documents.

No changes to config.json this run.

---

## 7. Action Items (ordered)

If the operator wants to implement these recommendations, order matters:

1. **Add the top-level nav bar to all four pages first.** Low-risk, high-value. Makes the current architecture coherent even before content changes.
2. **Dashboard: add the NP+DI Filter section at the top + replace the Patch SLA cards with the three-tier model.** This is the highest-leverage single change — it fixes the internal inconsistency and makes the periodicity result visible on the page that sees the most traffic.
3. **Index.html: rewrite the TL;DR and add the two periodicity-related bullets.** 15-minute change, immediate narrative improvement.
4. **Index.html: structural rewrite per Section 2.2 outline.** This is the big project. Probably 4-6 hours of careful editing to reorder sections, fold content, and cut the Section 7/8/9 dead weight.
5. **Index.html: add caveats and sensitivity section.** Can happen in parallel with #4.
6. **Dashboard: move Finance and Why-Most-Don't to expandables.** Cleanup, low priority.

cve-reference.html needs no changes.

---

## 8. Second-Pass Notes (added 2026-04-21, later same-day)

A re-read of the analysis and the earlier sections of this review surfaced six additional pushbacks and one missing comparison that the earlier review didn't fully develop. These are the things I would expect a hostile reviewer from a peer-research team to raise — not fatal, but each one should be addressed before the walkthrough rewrite lands.

### 8.1 The comparison benchmark is missing

The periodicity page compares NP+DI against **"rebuild on every C/H"** — a straw-man baseline that essentially no mature security team actually uses. The interesting comparison is against filters a CISO might plausibly already have in place: `CVSS ≥ 9.0 only`, `attack-vector:N + scope:changed`, `EPSS above 0.01`, or even `KEV-listed components only`. None of these alternative filters are applied to the same 129-CVE dataset for comparison. Without that, we can't tell whether NP+DI's 71–86% reduction represents real marginal value over the filters operators already use, or whether a CVSS-9-only filter would have produced similar numbers for free.

The right version of the periodicity page would have a "filter comparison" table: same 129 CVEs, five or six filters applied, reduction rate and miss rate for each. I suspect NP+DI still wins on the trigger-precision axis, but the case is unmade.

### 8.2 "Zero misses" is partly tautological

The filter was designed with the full 12-month history already visible. The "zero misses in 12 months" claim is therefore a backtest on the data used to design the filter — the same kind of look-ahead bias that makes quant-trading strategies look great in-sample and then underperform live. The honest framing is **"the filter achieves zero misses on the dataset it was constructed from,"** which is weaker than "the filter has never been wrong." The earlier review (Section 1.4) makes this point gently; the walkthrough should make it loudly.

**The corollary is that we should pre-register a forward-looking test now.** Concretely: commit in writing today that "no CVE currently classified as non-trigger on cve-reference.html will appear in CISA KEV by 2027-04-21; if any does, the filter missed." That's the out-of-sample test, and the current repo state is the pre-registration artifact. Without that commitment, any future write-up of "zero misses over 24 months" will rightly be dismissed as goalpost-moving.

### 8.3 The filter mostly recapitulates institutional priors, not independent discovery

The DI CWE set (78, 77, 22, 23, 36, 89, 94, 95, 918, 917, 1336, 116, 74, 75, 113, 93, 611, 91, 90, 79) is, essentially, the injection family as it already exists in CWE's taxonomy — the same family that has dominated KEV's library-level entries for a decade. Adding the NP step ("apply only to dependencies that parse network input") is intuitive and well-motivated by this project's own observational work, but it's not a data-driven discovery — it's an encoding of what the security community already knew and what Section 4 of index.html already argues.

This is a feature, not a bug (the filter is defensible precisely because it's boring). But the walkthrough should frame it as **"we formalized what experienced practitioners already do informally,"** not as a novel predictive model. The marketing value is operationalization, not insight. Overclaiming would be easy and should be avoided.

### 8.4 The April spike analysis has a circularity we haven't addressed

The Spring manifest had 8 C/H events in April 2026 versus 14 in the prior 11 months, all in network parsers. The periodicity page (Section "April 2026 Spike") hints — correctly — that this is consistent with a Glasswing/Mythos-style automated scan of parsing surfaces producing coordinated disclosure batches (Tomcat cluster Apr 9, Thymeleaf cluster Apr 15).

But if Mythos is producing the very bugs that are triggering the filter, then the claim "NP+DI triggers match what exploitation sources already know matters" has a feedback-loop risk: Mythos is scanning the parsing surface because the parsing surface is known to be the exploitation-likely one, producing CVEs in the parsing surface, which then validate a filter that flags the parsing surface. The analysis is still useful, but it measures the community's collective belief about what to scan for as much as it measures which bugs will be exploited.

**Recommendation:** if the April spike content moves into the walkthrough, flag this explicitly. One sentence: "AI-assisted discovery is increasingly focused on the same attack surface this filter highlights, which validates the targeting but makes the filter's apparent accuracy partly self-fulfilling."

### 8.5 The operational cost of Tier 2 is unquantified

The three-tier model recommends **monthly container rebuild** for Tier 2 (blast-radius control). The periodicity page shows the *benefit* of monthly refresh (worst-case privesc drops from 21 to 5) but never the *cost*. A monthly container refresh cadence across a 1,000-container fleet is not free — it's base-image builds, regression testing, staged rollouts, incident response during any breakage window. For most mid-size engineering orgs, monthly container refresh is *aspirational*, not *actual*.

The walkthrough's Section 10 (new outline) will be strengthened by a one-paragraph acknowledgment: **"The monthly cadence is operationally demanding; for teams currently on quarterly or yearly refresh cycles, the path to monthly is a separate engineering program, not a switch to flip."** Otherwise the model reads as an armchair recommendation.

### 8.6 The Django honest-weak-case framing understates a real limitation

The existing review (Section 1.2) argues the Django framing should flip — "Django is the worst case the filter handles, and it still delivers quarterly cadence." I want to push the opposite direction. Django's result is **4 genuine SQLi triggers in 12 months, all in the same component (the ORM)**. If any one of those SQLi CVEs turns out to share a root cause with the others (they appear to: all CWE-89, all in QuerySet/ORM internals), the "4 separate events" framing is misleading. It's really one persistent issue being patched iteratively. In which case the filter is either (a) correctly flagging the same class-of-bug four times, or (b) producing four trigger events that a single architectural fix would have eliminated.

The walkthrough should note this. Not as a weakness of the filter, but as a pattern: **recurring NP+DI triggers in the same component are a signal that the component has a structural issue, not just individual bugs.** That's genuinely actionable insight for the CISO.

### 8.7 Manifest selection is a bigger deal than acknowledged

The three manifests were chosen by the analyst team as "representative" of their ecosystems. They are **not** empirically-validated representatives — no poll of real Spring Boot apps, no aggregation of real Node.js package-lock.json files. For the cross-ecosystem convergence claim ("14-14-14 across three stacks") to mean anything, we need some reason to believe the manifests resemble production deployments.

One bounded test: **pull package.json / pom.xml / requirements.txt from a sample of 20-50 real open-source web apps** (there are plenty on GitHub), compute the median and IQR of NP-parser count and DI-trigger count, and check whether our three synthetic manifests fall inside that distribution. If they do, the convergence claim strengthens. If they don't, the 14-14-14 number is an artifact of manifest construction and should be demoted.

This is a ~1 day of analyst work and would materially strengthen the paper. It's the single highest-leverage thing we could add to the periodicity analysis before publishing to a wider audience.

### 8.8 Net summary for second-pass

None of these change the primary recommendations in Sections 1–7. The review's structural advice (restructure index.html around the prescriptive filter, replace Section 9's CVSS-tier SLAs, add periodicity-filter section to the top of the dashboard) stands. But two of the six points above should be reflected in the walkthrough rewrite:

- **Add a "what would other filters have produced" comparison section** to the new Section 9 (External Validation). CVSS-9-only, EPSS-threshold, KEV-listed-only. Same 129 CVEs. Shows NP+DI's marginal value explicitly.
- **Pre-register the forward-looking test in writing** in the new Section 12 (Caveats). Without it, the "zero-miss" narrative has a short shelf-life.

The other four (#8.3 priors, #8.4 circularity, #8.5 Tier 2 cost, #8.6 Django structural issue, #8.7 manifest validation) are nice-to-haves that would each add one paragraph.

---

## 9. Daily Scan Addendum — 2026-04-21 (later same-day)

Already covered in the main daily analyst report (`analyst-reports/2026-04-21.md`) and the daily-scan section above (Section 6). Re-verified at report-push time:

- **CISA KEV:** no additions since the 8-CVE batch on 2026-04-20. Catalog total 1,577. HTTP-parsing-adjacent share of April entries remains ~65%.
- **NVD April MTD:** 3,885 through day 21 (per refresh agent), consistent with ~185/day pace and a ~5,550 April extrapolation.
- **Glasswing attribution count:** 40, unchanged. Three Claude-in-credit-line CVEs (CVE-2026-4747 FreeBSD NFS, CVE-2026-5194 wolfSSL, CVE-2026-5588 Bouncy Castle), none in KEV.
- **Probable-participant self-scan table:** unchanged. Cisco SD-WAN Manager triplet disqualifies (pre-disclosure exploitation). OpenClaw cluster disqualifies (not a Glasswing participant product).
- **Watch list:** no entries moved to confirmed-KEV today. Marimo (CVE-2026-39987) now 10 days post-exploitation-observation with no KEV add — well within the 46-day Cisco-style gap established yesterday.
- **Thesis-challenge counter-examples:** still zero library/framework CVEs reaching KEV via non-HTTP vectors. Closest outstanding candidate is CVE-2026-33827 (Windows TCP/IP RCE) — 6 days post-disclosure, still not in KEV.

**Nothing today contradicts the periodicity review above.** The day's data (batch of 8 KEV entries, all HTTP-parsing-adjacent) is consistent with the thesis the periodicity filter is built on. No config.json changes this run.

---

*End of review (second-pass complete).*
