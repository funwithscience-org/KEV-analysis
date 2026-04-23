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

*End of second-pass review.*

---

## 10. Third-Pass Review — 2026-04-22

A day of substantial page evolution. Reviewing against the prior-day recommendations, I find most of the structural advice has already landed in the repo — index.html and dashboard.html now match the outline proposed in Section 2.2. Three new pieces of analytical work were also added today: **Netty as a 4th ecosystem, CWE-444 added to the DI CWE set, and a 7-year historical backtest against a real enterprise Java manifest**. This pass evaluates those additions, checks what's still outstanding from yesterday's punch-list, and appends today's daily scan.

### 10.1 What landed from yesterday's recommendations

Cross-referencing commit history against Section 7 (action items) of the 2026-04-21 review:

- ✅ **Index.html structural rewrite (action item #4).** The new section headings map cleanly to the 2.2 outline: §6 From Observation to Filter (NP+DI), §7 Cross-Framework Validation, §8 Kill Chain, §9 External Validation (Zero-Miss Window), §10 Three-Tier Patching Model, §11 Reverse Proxy Myth, §12 Mythos (demoted), §13 Watch List, §14 Caveats. The heavy-lift reorganization happened in the `index-v2.html → index.html` promotion (commit 4173854).
- ✅ **Dashboard: NP+DI Filter section at the top and Three-Tier Patching Model replacement for Patch SLA cards (action item #2).** `docs/dashboard.html` now leads with the NP+DI cross-framework chart and the hero-stat triple (14 → 2-4, zero misses, CVE reference link), and the Three-Tier section replaced the prior 72h/7d/30d framework. The internal inconsistency flagged yesterday is resolved.
- ✅ **TL;DR rewrite (action item #3).** The new index.html opens with "The Problem and What We Found" and leads with the prescriptive framing. Observational bullets follow, not lead.
- ✅ **Periodicity-specific caveats in §14.** The caveats section explicitly includes OSV severity coverage, CWE-20 ambiguity, and window sensitivity. (See also §10.4 below — one pre-registration gap still open.)
- ✅ **Top-of-page nav (action item #1).** Dashboard now links to Periodicity Analysis. Index.html's hero section also surfaces the filter-first framing.

Still open from yesterday's punch-list:

- ◻️ **"What would other filters have produced" comparison section (§8.1).** No CVSS-9-only / EPSS-threshold / KEV-listed comparison has been added. The External Validation section (§9 in the new outline) still validates NP+DI *against* other signals without running those signals as filters over the 129-CVE dataset. This remains the single highest-value unaddressed critique.
- ◻️ **Pre-registered forward-looking KEV test (§8.2).** The periodicity page still claims "zero misses in 12 months" without an explicit pre-registration commitment that the 113 non-trigger CVEs will remain KEV-free through a stated future date. Without that commitment, the zero-miss number has a decay problem.
- ◻️ **Operational cost of Tier 2 (§8.5).** The three-tier model still describes "monthly container refresh" as a benefit without a cost-side paragraph. Readers with 1,000-container fleets on quarterly cadence will notice.
- ◻️ **Real-world manifest validation for Spring/Express/Django/Netty (§8.7).** The 7-year real-enterprise-Java backtest added today (§10.3 below) addresses this partially for the Java stack — but only for the Spring-family ecosystem. Node.js, Django, and the Netty microservice stack are still synthetic.

### 10.2 Netty as 4th ecosystem — solid extension, with one reservation

The Netty stack (32 packages, 20 NP) produces 3 all-C/H dates and **1 NP+DI trigger — a 93% reduction**, the steepest of the four stacks. This is a useful addition because:

- It tests the filter on a *Reactive/microservice* Java stack rather than the servlet/MVC Spring stack, showing ecosystem diversity within Java.
- The single trigger is CWE-444 request smuggling (Netty chunked extension quoted-string bug, Mar 26) — not a result cherry-picked to be nice.
- The 360-day silence window is the longest across any stack and plays the hero-stat role that Node.js's 311-day window played yesterday.

**One reservation I'd raise:** the page notes candidly that "without the CWE-444 addition, this stack would have had zero NP+DI triggers in 12 months." That's simultaneously the best and worst data point for the filter. Best: it demonstrates that adding a missing injection CWE class immediately caught a real smuggling vulnerability (the page correctly frames this as validation of the filter's responsiveness to input). Worst: it means the Netty result depends on a CWE class that was only added *today* — which is unavoidable ex post facto but worth naming.

The walkthrough currently presents CWE-444 in a footnote citing Nathan Dornbrook's external flag (`fn-444`, around line 1238). The footnote is appropriately honest. But the *headline number* ("93% reduction") is now in some sense an in-sample result for CWE-444 — the class was added after the Netty Mar 26 bug was already visible. A reader doing a close read will notice. Recommendation: in the headline or callout, add a short qualifier — *"93% reduction including CWE-444, which was added to the DI set in April 2026 after external review"* — so nobody has to dig into the footnote to find the caveat.

A second, smaller concern: the Netty manifest at 32 packages is noticeably smaller than Spring (48), Node.js (45), Django (40). The "14-14-14" convergence claim is weakened by Netty's 3-events baseline — it doesn't converge to 14, it sits well below. The walkthrough should add a sentence: *"The 14-14-14 convergence holds among manifests of comparable size; smaller manifests produce lower absolute counts but the reduction ratio is preserved."* Otherwise the convergence narrative gets muddied by the Netty outlier.

### 10.3 The 7-year real-enterprise-manifest backtest — the biggest strengthening of the analysis

This is the single best thing that's happened to the periodicity page since yesterday. 93 C/H dates across Q4 2018 – Q2 2026, collapsed to 22 NP+DI dates and 19 patch events (after 7-day clustering) — an 80% reduction over seven years, with the filter correctly firing on Log4Shell (Dec 2021), Spring4Shell (Mar 2022), Tomcat request smuggling, XStream RCE clusters, and SpEL injection.

**Why this is load-bearing:**

1. **It addresses the look-ahead bias concern from §8.2.** The yearly table shows how the filter would have performed in years when it didn't exist yet. If the filter had been in production in 2021, it would have fired on the XStream triple-disclosure (Aug 25) and the Log4Shell cluster (Dec 9-14) and skipped everything else. Those are exactly the two rebuilds you'd want to have triggered. This isn't the pre-registered forward test I recommended, but it's the next best thing: backtesting on data that was produced *before* the filter was designed.
2. **It catches the two canonical Java-ecosystem emergency events.** If the filter had missed Log4Shell or Spring4Shell, the analysis would collapse. That it catches both, and catches them as patch-event clusters (Log4Shell + follow-on + jackson = one 5-day cycle, not three separate fires), is a strong affirmation.
3. **The 2022 result is the sharpest answer to the "deserialization straw-man" critique.** 20 C/H dates, 15 of them jackson-databind CWE-502 disclosures, and the filter correctly ignored every one — firing only on Spring4Shell and a Tomcat smuggling bug. This is the clearest single-year data point that "the filter rejects deserialization noise without missing real exploits."
4. **The 2026 partial year (4 C/H dates, 0 NP+DI triggers) is honest.** The page doesn't hide that the current year's result is 100% reduction specifically because no smuggling/traversal/injection CVEs have hit the real-enterprise manifest yet in 2026. That's brittle — one CVE could change it — but the page doesn't claim otherwise.

**What I'd push back on:**

- **The "patch events" collapse (7-day clustering) is introduced without prior definition.** A reader comes to the chart and sees 22 NP+DI dates but only 19 patch events, with the reduction calculated from patch events. This is reasonable (if you're already in an incident, overlapping CVEs don't double the cost), but it also lowers the denominator in a way that makes the reduction look stronger. The walkthrough should explicitly note: "Reduction percentages in the yearly table use patch events, not raw CVE counts; using raw CVE counts gives an 76% reduction instead of 80%." Minor but worth stating.
- **Manifest selection is still the live concern.** The real-enterprise manifest is 60 libraries from "a portfolio of Spring apps" — better than synthetic, but still one organization's choices. Yesterday's §8.7 recommendation of polling 20-50 real open-source GitHub manifests remains outstanding. The 7-year backtest *replaces* the synthetic-Spring manifest validation; it doesn't generalize to Node.js or Django. **One real enterprise Java manifest doesn't remove the cross-ecosystem manifest-selection concern.**
- **2019-2024 averaged ~12 C/H dates/year in this manifest.** That's close to the synthetic-Spring 14/year figure but the variance is wide (3 → 20 → 5). A single-year snapshot of any stack is window-dependent; the multi-year backtest makes that concrete. The walkthrough could use this to strengthen the argument: "The 12-month window in our synthetic backtest could have looked quite different if it had ended in 2021 or started in 2018; the 7-year backtest shows the filter's performance is stable across those variations."

### 10.4 CWE-444 addition — worth doing, worth disclosing more loudly

CWE-444 (HTTP Request Smuggling) was added to the DI CWE set today after Nathan Dornbrook flagged CVE-2025-55315 (ASP.NET Core smuggling, CVSS 9.9). The footnote at index.html line 1238 documents the provenance honestly: 182 CVEs in NVD carrying CWE-444, all on network parsers, one prior KEV entry (CVE-2022-22536 SAP). Adding it reclassified two Tomcat smuggling CVEs in the enterprise manifest backtest (23 → 25 NP+DI) and turned the Netty result from zero triggers to one trigger.

**The principle is sound.** HTTP request smuggling is exactly the kind of network-parser direct-injection the filter is designed to catch — the original DI set omitted it through oversight, not by intent. Adding it makes the filter more complete, not looser.

**But this is a second instance of in-sample CWE-set expansion.** The first was CWE-918 (SSRF) and CWE-611 (XXE) in the original construction. The pattern — "we noticed we missed a class, we added it" — is legitimate but it means the DI CWE set is not fully pre-registered. A future reader could reasonably ask whether additional classes will be added later to capture newly-emerging injection patterns (AI-prompt injection, for example, which doesn't have a stable CWE assignment yet).

**Recommendation for the walkthrough:** add a sentence to §6b (The DI CWE Set) that explicitly names this practice — *"The DI CWE set is versioned. CWE-444 was added on 2026-04-22 after external review. We will add new CWE classes when they represent genuine network-parser direct-injection patterns, and we disclose such changes transparently. The filter's validation numbers are re-run against the current set whenever it changes."* This makes the pattern a feature, not a quiet change log.

**The bigger-picture note:** the filter's value is not that the CWE set is fixed; it's that the filter is *explicit* about what's in and out. A CVSS-9-only filter doesn't have this property — its threshold is fixed but the definition of CVSS-9 shifts over time with NIST/FIRST rescoring. The NP+DI filter's versioned CWE set is a feature that should be framed as such, not apologized for.

### 10.5 Dashboard: one stale chart

Small operational note: the dashboard's `crossFrameworkChart` (line ~780) still renders **3 frameworks** (Spring, Node.js, Django) at 2/2/4 NP+DI triggers vs 14/14/14 all-C/H. The periodicity page now includes Netty. The dashboard chart should be updated to 4 bars (adding Netty at 1 NP+DI vs 3 all-C/H, with the 93% reduction called out).

Also: the "Chaining Exposure" chart (`chainingChart` around line 805+) and the three-tier card section are correct and matched to periodicity.html. Only the cross-framework chart needs the Netty add.

### 10.6 Cross-page architecture — now coherent

The four-page architecture from yesterday's §4 is now largely in place. Checking against the table:

| Page | Role | Today's state |
|---|---|---|
| index.html | Narrative walkthrough | ✅ Restructured to new outline. Leads with problem-framing, ends with watch list + caveats. |
| dashboard.html | Live data exhibits | ✅ Leads with NP+DI section; three-tier model replaces old SLA cards. One chart stale (crossFrameworkChart missing Netty). |
| periodicity.html | Deep-dive technical | ✅ Extended today with Netty + 7-year backtest. |
| cve-reference.html | Audit trail | ✅ Now has CVE numbers alongside GHSA and a CSV download. |

Nav: dashboard links to periodicity. Index links to dashboard. Periodicity.html should grow a top-of-page nav bar matching the other three; today it's still a standalone deep-dive without obvious links back to index.html or dashboard.html. Low-priority cleanup.

### 10.7 Second-order concerns surfaced by today's additions

Three observations that weren't relevant yesterday but are relevant now:

**(a) The real-enterprise-manifest backtest inadvertently strengthens the observational case for §3.** The 7-year timeline shows that jackson-databind, SnakeYAML, XStream — the big deserialization-CVE factories — produce lots of CVEs but near-zero KEV entries. This is exactly the observational pattern §3 of the walkthrough argues for (network-parser injection is the exploitation signal; deserialization is the volume generator). The §3 narrative should cite the real-manifest backtest as corroboration. Currently §3 uses only the CVSS-severity-by-stack-layer data; adding one paragraph pointing at the 2018-2026 real-manifest timeline would strengthen the observational foundation.

**(b) Log4Shell is now a validated filter-catch and should be a callout.** "Log4Shell was caught" is a stronger sentence than "the filter works across ecosystems." It's the single most famous Java CVE of the decade and the backtest confirms the filter would have fired on it. The walkthrough should promote this to a hero callout — probably in §7 (cross-framework validation) or the §10.3 equivalent.

**(c) The 93 → 22 → 19 funnel is a cleaner teaching example than the 14 → 2 synthetic-stack number.** The synthetic stacks produce pedagogically clean numbers but require the reader to trust that the manifest is representative. The real-enterprise 7-year funnel produces messier numbers but is less vulnerable to the "it's a toy manifest" pushback. When writing the walkthrough's TL;DR, consider leading with "93 C/H events → 19 patch events in a real Java manifest over 7 years (80% reduction)" instead of or alongside the 14-14-14 synthetic convergence — the real-data number is more persuasive to a skeptical CISO.

### 10.8 Net summary for third-pass

The periodicity analysis has materially strengthened in 24 hours. The two biggest wins are the 7-year real-manifest backtest (which partially retires the §8.7 manifest-selection critique for Java) and the Netty addition (which tests a 4th ecosystem and validates the CWE-444 addition). Most of yesterday's structural recommendations for index.html and dashboard.html are now implemented.

The four unaddressed items from yesterday's punch-list remain worth doing:

1. **Alternative-filter comparison table** (CVSS-9, EPSS, KEV-only over the 129-CVE dataset) — highest value.
2. **Pre-registered forward-looking KEV test** for non-trigger CVEs through a specific future date.
3. **Tier 2 operational cost paragraph** for the monthly container refresh recommendation.
4. **Cross-ecosystem manifest validation** (real Node.js and Django manifests, not just synthetic).

New items specific to today:

5. **CWE-set versioning disclosure** in §6b. Call out the practice, don't hide it in a footnote.
6. **Dashboard cross-framework chart update** to include Netty (4th bar).
7. **Periodicity.html top-nav** back to index.html and dashboard.html.
8. **Log4Shell-caught callout** in §7 or §7g of the walkthrough. This is a marketing hero-stat sitting unused.

Nothing observed today weakens the core conclusions. The prescriptive case is sharper now than it was 24 hours ago, and the 7-year Java backtest is the most convincing piece of evidence the project has produced.

---

## 11. Daily Scan — 2026-04-22

Per the refresh agent output in `kev-tracking.json` (last_run 2026-04-22T03:10:00Z) and cross-checked against today's commits:

- **CISA KEV:** still 22 April entries. Catalog version rolled from 2026.04.20 → 2026.04.21 overnight but *contents unchanged* — no new adds since the 8-CVE batch on Apr 20. Dry spell resumes (1 day). Apr total is on pace with Q1 monthly average (~24).
- **NVD April MTD:** 4,227 through day 22, extrapolates to ~5,764 (up from 5,547 yesterday). The +342 overnight delta is almost entirely back-population: Apr 21 same-day count moved 35 → 359 as NVD caught up. Apr 22 same-day is only 18. Underlying daily rate stays near 192/day. Still ~9% below March (6,304) and well below all Glasswing-inflation projections.
- **W17 partial:** 543 across 3 days (~181/day). Too early to call an inflection; expect ~900-1000 final after back-population.
- **Glasswing attribution count:** 40, unchanged. Three Claude-in-credit-line CVEs (CVE-2026-4747 FreeBSD NFS, CVE-2026-5194 wolfSSL, CVE-2026-5588 Bouncy Castle). None in KEV. InfoQ citation of **"CVE-2026-31402" as a Linux NFS heap overflow (23-year bug) found by Carlini with Claude Code** needs analyst deduplication — likely conflation with CVE-2026-4747 FreeBSD NFS. Flagging for tomorrow's agent run.
- **New Claude-assisted non-Anthropic CVE:** **CVE-2026-34197 (Apache ActiveMQ)** added to KEV on 2026-04-16; per Horizon3.ai disclosure, found by Naveen Sunkavally using Claude (~10 min attack-chain trace). This is the first publicly-credited third-party (not Carlini/Anthropic) Claude-assisted CVE to reach KEV. Pattern-significant: it means Claude-the-research-tool is producing exploitation-grade findings outside Project Glasswing, which materially expands the story the walkthrough tells about AI-assisted discovery. Not a probable-participant-self-scan (Apache isn't a Glasswing participant). But worth a line in Section 12 (Mythos) about the *non-Glasswing* Claude-assisted discovery channel.
- **Probable Glasswing participant self-scan candidates flagged by refresh agent:** 
  - **CVE-2026-40050 (CrowdStrike LogScale, CVSS 9.8, CWE-22 + CWE-306)** — unauthenticated path traversal on an HTTP log-ingest endpoint. CrowdStrike is a Glasswing participant. This is the strongest probable-self-scan candidate of the week. Analyst verification needed: credit line on CrowdStrike's advisory. If no third-party researcher is credited, this should be added to `probable_participant_cves` in config.json.
  - **CVE-2026-20093 (Cisco IMC, CVSS 9.8)** and **CVE-2026-20160 (Cisco Smart Software Manager On-Prem, CVSS 9.8)** — both Cisco (Glasswing participant), both HTTP-adjacent. Analyst verification needed on credits.
  - **CVE-2026-24164 (NVIDIA BioNeMo, CVSS 7.8, CWE-502)** — NVIDIA (Glasswing participant). Deserialization rather than HTTP parsing, so fits a broader "automated-scan" pattern than the strict NP+DI filter. Review candidate, not clear add.
  - **CVE-2026-1386 (AWS Firecracker jailer)** — AWS (Glasswing participant), but symlink/local attack vector — disqualifies for NP+DI but still participant-self-scan-relevant.
  - **CVE-2026-39861 (Anthropic Claude Code sandbox, CVSS 7.7, CWE-22 + CWE-61)** — sandbox → workspace symlink escape. Anthropic is the Glasswing *principal*, not just a participant. Local attack vector removes NP+DI relevance, but a participant-self-scan framing does cover "Anthropic dogfooding on its own product."
- **Watch list:** no entries moved to KEV today. Thymeleaf SSTI pair (CVE-2026-40477/-40478) still functional/PoC-only, wolfSSL and Cisco ISE/Webex quad still no-public-PoC.
- **NP+DI candidate sweep new flags:** refresh agent surfaced CVE-2026-21571 (Atlassian Bamboo CWE-78, CVSS 9.4), CVE-2026-40887 (Vendure e-commerce CWE-89, CVSS 9.1), CVE-2026-40906 (ElectricSQL CWE-89, CVSS 9.9), CVE-2026-40911 (WWBN AVideo WebSocket CWE-94, CVSS 10.0), CVE-2026-41193 (FreeScout CWE-22 zipslip, CVSS 9.1), CVE-2026-40576 (excel-mcp-server CWE-22, CVSS 9.4), CVE-2026-40520 (FreePBX GraphQL CWE-78, CVSS 8.6). All are textbook NP+DI pattern candidates. CVE-2026-40576 is interesting — first MCP server in our candidate set, and MCP transport exposure is a growth surface worth watching.
- **Thesis challenge / counter-examples:** still zero. No library/framework CVE has reached KEV via non-HTTP vector in the tracked window. CVE-2026-33827 (Windows TCP/IP RCE) — 7 days post-disclosure, still not KEV — remains the closest outstanding contender but also remains product-level, not library.
- **Today's MS/RHEL/volume numbers:** MS Patch Tuesday April 2026 = 163 (unchanged, second-largest PT ever). RHEL 8 April = ~23 (low-confidence estimate, stack.watch still returns YTD aggregate only).

**Nothing today contradicts the periodicity review.** The CrowdStrike LogScale advisory is the single most material new signal — if confirmed as a participant self-scan, it materially strengthens the Mythos-adjacent discovery narrative and gives us a 5th probable-self-scan CVE. No config.json changes this run (analyst verification needs to happen before the CrowdStrike CVE enters the tracked list).

---

*End of review (third-pass complete, 2026-04-22).*

---

## 12. Addendum — Exploitation Evidence Added to Real-Manifest Table (commit 538a475)

Noticed immediately after my first push: a commit landed (538a475, "Add exploitation evidence to real-manifest periodicity table") that materially revises the zero-miss narrative. The revised page now discloses:

- **5 exploited CVEs across 19 patch events in the 7-year Java manifest:** 4 in CISA KEV (Log4Shell, Log4Shell follow-on, XStream RCE via VMware NSX, Spring4Shell) + 1 Metasploit-only (Tomcat CVE-2019-0232). All 5 were caught by the NP+DI filter. Good.
- **3 filter misses (CVEs in this manifest that reached KEV but were NOT flagged by NP+DI):**
  1. **CVE-2020-1938 (Tomcat "Ghostcat" AJP file read)** — classified CWE-269 (improper privilege management); should arguably be CWE-22 (path traversal) since the bug is arbitrary-file read via AJP. DI filter missed it because CWE-269 isn't in the DI set.
  2. **CVE-2025-24813 (Tomcat HTTP PUT deserialization RCE)** — classified CWE-502 only; the filter intentionally excludes pure CWE-502 (to filter deserialization noise), but this specific bug is triggerable via HTTP PUT, which puts it in the grey zone between "deserialization noise" and "network-parser direct injection."
  3. **CVE-2026-34197 (ActiveMQ Jolokia RCE)** — classified CWE-20 (generic input validation); should be CWE-94 (code injection). The filter missed it because CWE-20 alone isn't in the DI set.

### 12.1 This is important intellectual honesty — and it changes the headline

The "zero misses" claim I was evaluating in §1.4 and §10.2 above is no longer strictly correct. The corrected claim is: **zero misses where CWE classifications are correct; three misses where NVD's CWE assignment is wrong or incomplete.**

This is a *better* story than the literal zero-miss claim, not a worse one. Here's why:

- **The 3 misses all share a root cause** (CWE misclassification by NVD/CNAs), which means the failure mode is specifiable and addressable — it's not "random bugs slip through."
- **The proposed mitigation (the "AI safety-net recommendation" the commit references — automated CWE validation for NP-but-not-DI advisories) is both concrete and testable.** A reviewer asking "how do you know the 3 misses are the full miss set?" has an answer: run an automated CWE-validation sweep over every NP-library advisory that was NP-but-not-DI; if the sweep flags additional CVEs, those are additional misses.
- **It resolves the §8.2 concern from yesterday's second pass** ("zero misses is partly tautological because you designed the filter on the data"). The three misses are disclosed openly, they share a structural cause, and the mitigation is distinct from the filter itself. That's more defensible than a literal zero.

### 12.2 What this means for the walkthrough and dashboard

- **The index.html TL;DR and §7/§9 callouts need to shift from "zero misses" to "zero misses within correctly-classified advisories; three misses attributable to CWE misassignment, all specifiable."** The *number* loses its marketing polish but the *story* strengthens.
- **The dashboard's "zero misses" hero-stat needs the same update.** Replace "0 skipped events later appeared in KEV" with "3 misses across 7 years, all CWE-misclassification; see reference."
- **The AI safety-net recommendation should be promoted into the walkthrough's §7g or §10.** It's the single most actionable operator-facing addition of the week — "here's the filter, here's the known failure mode, here's the proposed mitigation." That's a complete operational argument.
- **CVE-2026-34197 (ActiveMQ Jolokia) is both a filter miss AND the Claude-assisted Horizon3.ai disclosure from today's daily scan.** This is a useful cross-reference: the same CVE serves as (a) a filter-miss case study, (b) a Claude-as-research-tool attribution datapoint, and (c) a live-24h KEV add. The walkthrough's Mythos section (§12) and periodicity section (§7g) should cross-link on this CVE specifically — it's a rare example of a CVE that illuminates multiple threads of the analysis at once.

### 12.3 Remaining exposure

Two questions the revised page doesn't yet answer:

1. **Are there non-manifest CWE-misclassification misses?** The 3 disclosed misses are manifest-internal. A CWE-sweep over the full library CVE universe (not just this manifest) could surface more. Worth a paragraph acknowledging that "the 3 misses are what we've found in this manifest; the rate in the wild is unmeasured." Being conservative strengthens the case.
2. **Is the AI safety-net recommendation actually implemented or just proposed?** The commit message mentions it; the page references it. Operationally, is there a script running over new NP-advisory CWE assignments flagging ambiguities for human review? If yes, say so and describe it. If proposed-only, say that too. The honesty on the 3 misses is the biggest intellectual-honesty asset the page has acquired in weeks — double down on it by being explicit about what's built vs. what's planned.

### 12.4 Updated punch-list (post-addendum)

Adding to the §10.8 list:

9. **Update the zero-miss callouts on index.html and dashboard.html** to reflect the 3-miss disclosure. Highest-urgency copy change across both pages — the current headline text is no longer accurate.
10. **Promote the AI safety-net recommendation to a §7g or §10 callout** in the walkthrough. This is the operational payoff of the miss-analysis and it's currently buried in `<details>`.
11. **Run the CWE-validation sweep over the full NP-library universe** (not just this manifest). If additional misses surface, disclose them. If not, the 3-miss number strengthens.

Nothing about this addendum changes my overall assessment from §10.8: the analysis is materially stronger than it was 24 hours ago. If anything, the disclosure of 3 misses with a specifiable root cause and proposed mitigation is the single most analytically sophisticated thing the project has published.

---

*End of review (third-pass + addendum complete, 2026-04-22).*

---

## 13. Fourth-pass review — 2026-04-23

I re-ran the full review today against the current HEAD (commit `7251fbd`, 13 commits ahead of where I stopped yesterday). Most of what passes 1–3 recommended is now in the repo. This pass is deliberately short, specific, and devil's-advocate-heavy because the remaining gaps are smaller and more interesting than the ones we started with.

### 13.1 TL;DR — where the restructuring landed

**Implemented since pass 3:**
- Walkthrough is fully restructured into 14 sections matching the narrative arc recommended in §1 and §2. NP+DI filter is §6 with explicit 6a/6b/6c sub-structure. Cross-framework validation is §7 with the seven sub-parts including the real-manifest backtest (§7d) and the three-miss disclosure (§7e–7f).
- Kill-chain "Land & Expand" framing is §8 with the OS privesc dependency argument integrated (commit `dc78d30`).
- Three-tier patching model is §10 with the WAF Dividend callout as §10a (per the §3 recommendation yesterday).
- Dashboard now leads with an NP+DI Filter section at the top (line ~155–170), including a twin-button link to periodicity.html and cve-reference.html — the "front door" navigation recommended in §4 is wired.
- Top-of-page nav bar on all four pages (Walkthrough / Dashboard / Periodicity / CVE Reference) with current-page highlighting. Cross-page architecture is cleanly linked.
- EPSS comparison is reframed around operational speed, not distributional mean/median (commit `34a2051`). The "NP+DI + AI scan = 8/8 on day 0, EPSS ≥ 0.10 = 1/8 on day 1" hero-stat is exactly the framing §9 and §10 kept asking for.
- Real-manifest backtest discloses the 5 exploited CVEs and the 3 CWE-misclassification misses explicitly in both §7d and §7e. This is the intellectual-honesty upgrade §12 called for.
- AI safety-net recommendation is promoted into §7e and §7f rather than buried in a `<details>` — commit `b7e7b8a` shows the "16% NP+DI vs 3% NP-only vs 0% non-NP" framing.

**This is a lot of work in ~30 hours. The remaining gaps are narrower.**

### 13.2 Four-section assessment (what remains)

#### Section 1 — Assessment of the Periodicity Analysis

The periodicity analysis is in good shape. Three points stand out today that prior passes didn't flag:

**Holds up well:**
- The three-tier patching model (Emergency / Monthly / Release-cycle) is now framed around **blast radius, not severity**. That's a meaningful conceptual upgrade — it means the tier isn't "how scary is this CVE" but "how much of the deployment do I need to touch to patch it?" This is the right framing for ops.
- The EPSS comparison in §9 is operationally defensible now. "Day 0 vs Day 1" is a testable claim; "our mean is lower than EPSS's mean" was not.
- The 3-miss disclosure, paired with the AI safety-net recommendation, is unusually honest for a vendor-pitch-style analysis page. It materially strengthens the case.

**Remains overclaimed:**
- The dashboard's hero insight at line 160 still reads **"zero misses — no filtered-out CVE has appeared in CISA KEV."** This is the exact claim §12.4 item #9 flagged as no-longer-accurate. The walkthrough §7e has been updated with the 3-miss disclosure; the dashboard has not. This is a five-minute copy edit and it should be done before anyone external reads the dashboard page. The two pages are now internally inconsistent.
- Walkthrough §9 title is still "External Validation: The Zero-Miss Window." Its hero-stat row (`8/8 NP+DI + AI scan catches on day 0`) is correct — that's the 5-exploited + 3-miss total restated as "with AI safety-net applied, 0 missed." But the section intro line 599 still says **"Zero misses across 113 non-triggers"** and line 919 still describes the claim as **"12 months of zero misses."** Both need to be revised to match §7e's honesty. The fix is small: say **"Zero misses within correctly-classified advisories; three misses traceable to CWE misassignment, all specifiable and catchable by an automated CWE-validation pass."** That's the story. The current wording buries it.
- The "testable metric" framing in §13 of the walkthrough ("your filter should produce zero misses") should be softened to **"your filter + AI safety-net should produce zero KEV misses; track CWE-classification disagreements as a leading indicator."**

**Devil's-advocate pressure points that the current draft doesn't fully answer:**

1. **Backtest freshness.** The 7-year Java manifest ends somewhere around early 2026 but today's daily scan shows CVE-2026-34197 (ActiveMQ Jolokia) — both a filter miss AND a Horizon3.ai Claude-assisted disclosure that hit KEV on 2026-04-16. Has that CVE been folded into the manifest case study yet? Grep shows it referenced in §12 (Mythos) but I don't see it called out in §7e/7f as a 2026 real-time validation of the miss set. It should be. It's the best possible validation: the page predicts the failure mode (CWE-20 assignment hides a CWE-94 bug), and the failure mode fires 30 days later with a live KEV entry.
2. **Selection-bias critique survives.** Pass 2 flagged that the manifest is curated (popular Java libraries, not a random draw). The current §7d discloses the 60-library count but doesn't explicitly address why these 60 and not others. A paragraph of form "manifest selected to maximize HTTP-parsing surface — exactly the CVE class the filter targets; a manifest of purely computational libraries would produce trivially-zero NP+DI hits and would not validate the filter" would preempt the obvious criticism. One paragraph.
3. **No quantified cost-of-rebuilds baseline.** The three-tier model claims 71–86% reduction in rebuild-trigger dates. But what does a rebuild cost an operator? Hours of CI time, deploy coordination, rollback risk. If the answer is "pennies because CI is free and deploys are continuous," the tier model's value is smaller than the claim implies. A single sentence acknowledging "the reduction matters proportional to rebuild cost; for shops with continuous deployment the savings are smaller" would disarm the cheap shot.
4. **Non-HTTP library exploitation bias.** OSV survey shows ~93,000 ecosystem-wide C/H; our 177-library sample pulls 770. That's a ~0.8% sample. The filter's performance on the 99.2% we haven't looked at is unknown. The walkthrough §6c hints at this but doesn't land the point: **the filter's validity hinges on the claim that exploitation is concentrated in the 1% of libraries that parse network input.** If a reviewer pushes back ("but what about the 92,230 C/Hs you didn't examine?"), the answer is "those libraries aren't network-parseable, so the filter trivially deprioritizes them; the open question is whether any of them become exploited, which would be evidence *against* the filter." That's the argument — write it down.

#### Section 2 — Walkthrough Restructuring (what's left)

The restructuring is largely done. Outstanding items:

1. **Update §9 intro copy to match §7e honesty.** Swap the literal zero-miss claim for the corrected CWE-classification-caveated version. Reframe §9's title from "The Zero-Miss Window" to something like "Cross-Validation Against Five Exploitation Databases" — the analytical content is what matters, the marketing headline hurts the credibility upgrade §7e delivered.
2. **Add a §7e.5 (or §7f sub-bullet) for the 2026-04-16 ActiveMQ Jolokia live-fire validation.** Quote: *"On 2026-04-16, 30 days after publishing this analysis, CVE-2026-34197 (Apache ActiveMQ Jolokia RCE) was added to CISA KEV. The filter missed it — CVE-2026-34197 was assigned CWE-20 (generic input validation) rather than CWE-94 (code injection). This is the exact failure mode §7e predicted. The AI safety-net pass would have flagged it on publication date."* That's the pitch. Write it.
3. **Soften §13 ("your filter should produce zero misses") to "your filter + AI safety-net should approach zero misses; track CWE disagreement as leading indicator."** One-line edit.
4. **Add the "why these 60 libraries" paragraph to §7d.** Preempt the manifest-selection-bias critique in one paragraph. §2.b above.
5. **Add a sentence to §10 (three-tier model) about rebuild-cost dependency.** §2.c above. One sentence.
6. **Sidebar TOC doesn't update for sub-sections.** Minor but: sidebar currently lists only top-level (1–14); the deep structure (6a/6b/6c, 7a–7g) is invisible in navigation. A reader scanning the sidebar won't know §7 has seven sub-parts. Consider a collapsed sub-TOC or one-level-deep sidebar expansion.

**What to keep as-is:** sections 1–8 are in good shape. Section 11 (Reverse Proxy Myth), Section 12 (Mythos Detector), and Section 14 (Caveats) read well. The real-manifest case study (§7d) is now arguably the strongest single section of any page in this repo.

**What to cut:** nothing. Every section is pulling its weight. The urge to cut the long library-exploitation caveats in §6c should be resisted — they're what make the NP+DI thesis survive a skeptical read.

#### Section 3 — Dashboard Updates

Dashboard leads with NP+DI. That's right. Remaining items:

1. **Fix the line-160 hero insight zero-miss claim.** Replace with *"…reduces rebuild-trigger dates by 71–86% with 3 CWE-misclassification misses across 7 years of manifest history, all catchable with an AI-assisted CWE validation pass — see periodicity page."* This is the single most urgent edit across all four pages; the two pages currently contradict each other on the filter's miss count.
2. **Add a miss-disclosure chart or stat to the NP+DI section.** One card showing "5 exploited CVEs in manifest / 4 caught by NP+DI / 3 additional KEV entries missed (CWE-misclassified) / 0 missed with AI safety-net." That's the honest version of the 71–86% hero number. It converts the single-metric headline into a two-layer accuracy claim, which is more defensible under pressure.
3. **Consider moving the "Three-Tier Patching Model" section closer to the NP+DI section.** Currently it's after CWE Families and Mythos Detector; logically it's the operational consequence of NP+DI and belongs adjacent. This is a taste call, not a must-do.
4. **Redundancy audit.** The dashboard and walkthrough both have: (a) NP+DI hero stat; (b) the 12-month periodicity chart; (c) the three-tier model; (d) the watch list. That's expected for an overview-vs-explainer split but the content is near-duplicate. Pick one authoritative version per page: dashboard = the numbers + link out; walkthrough = the numbers + the argument. Today the dashboard is ~40% dashboard-only content and ~60% mini-walkthrough; I'd lean it further toward "numbers only, click through for why."
5. **KPI tile for NP+DI effectiveness.** Suggestion: a top-row KPI card on the dashboard showing something like `16% / 3% / 0%` (NP+DI / NP-only / non-NP exploitation rate in the manifest). That's the single most actionable number in the entire analysis and it currently lives only in the walkthrough.

#### Section 4 — Cross-Page Architecture

Four pages now: Walkthrough (index.html), Dashboard, Periodicity Analysis, CVE Reference. Top-of-page nav is wired. That's clean.

**Current architecture:**
- **Dashboard** = entry point, charts-first, minimal prose. Link-out to walkthrough and periodicity.
- **Walkthrough** = the argument, long-form, methodology-first.
- **Periodicity** = the detailed case study (cross-framework + real-manifest backtest).
- **CVE Reference** = the raw per-CVE classification table.

**Open question: is the dashboard the right front door?** A skeptical CISO landing on the dashboard sees charts + a link row but doesn't immediately encounter the argument. If the argument is the point, the walkthrough is the front door; the dashboard is the appendix. Today the site defaults to the walkthrough path (index.html is the walkthrough), which is the right call — but the cross-page nav treats dashboard as coequal with walkthrough, which slightly underweights the walkthrough's primacy. Minor: consider making "Walkthrough" the visually-dominant nav item (e.g., first position, bolded).

**Evergreen.html is unlinked.** Grep confirms no page references docs/evergreen.html. It's currently a scratch page with 5 months of analysis. Two options: (1) integrate it into the walkthrough as a supporting case study (likely §7 or §10), or (2) explicitly mark it as scratch in a README/index comment so future analysts know it's not production. Today it's in limbo.

**CVE Reference page is under-promoted.** It's the most rigorous piece of per-CVE classification work we've published and only gets a tiny link-out on the dashboard and a nav-bar entry. Consider a brief callout on the walkthrough — "every claim in this page is backed by per-CVE classifications in the CVE Reference. Each claim is auditable." That's a credibility asset we're not currently cashing.

**Navigation heuristic I'd suggest:** a reader scanning the sidebar of any page should be one click from (a) the argument, (b) the charts, (c) the case study, and (d) the raw data. Today the top nav does this but the sidebars don't — only the walkthrough has a rich sidebar. Consider adding a minimal "See also" footer to periodicity.html and cve-reference.html pointing back to the main walkthrough + dashboard.

### 13.3 Daily scan — 2026-04-23

Today's refresh run (kev-analysis-refresh 05:03 local, kev-tracking.json timestamp `2026-04-23T05:05:00Z`):

- **KEV catalog unchanged for 3 consecutive days.** Catalog version `2026.04.21`, released 2026-04-21T17:10:43Z. April total still 22. CISA ran a heavy surge 2026-04-20/21 (the 8-entry HTTP-parsing sweep logged in rolling.md) and has been quiet since. This is a normal pattern — KEV additions are bursty, and the ~24/month Q1 2026 average holds.
- **NVD April MTD = 4,593 on day 23.** Extrapolates to 5,991 full-month (up from 5,764 yesterday; back-population continues, Apr 22 finalized at 355 vs. the 18 we saw 24h earlier). Daily pace steady at ~186/day for fully-populated days. This puts 2026 on track for the largest-ever single CVE year, continuing the Q1 trend.
- **Glasswing/Mythos total: 283 Mythos-linked fixes.** No new additions today. The Firefox 150 disclosure (271 fixes, 41 CVE-tier, 3 Claude-credited: CVE-2026-6746, -6757, -6758) remains the dominant contributor. The 271 number is Mozilla's internal characterization; only 41 are CVE-tier and only 3 are explicitly credited to Claude in MFSA 2026-30. The config.json note already disclaims this — keep the "Mythos-linked fixes" vs. "Claude-credited CVEs" distinction. I don't see a reason to shift the framing today.
- **Watch list:** no movement. Thymeleaf SSTI pair (CVE-2026-40477/-40478) still PoC-only. wolfSSL and Cisco ISE/Webex quad still no-public-PoC. CVE-2026-33825 (Windows Defender BlueHammer, Patch Tuesday disclosure, PoC on GitHub since Apr 3) is the single most conspicuous no-KEV-yet CVE on the list — it's been nearly three weeks with public PoC and CISA hasn't listed it. Either they're using something else to gate inclusion (active exploitation in the wild, not just public PoC) or the Apr 3 PoC wasn't weaponized. Worth a 2-line note in tomorrow's rolling.md.
- **Probable participant self-scan status:** the four Cisco ISE/Webex CVEs (20180, 20186, 20147, 20184) remain the headline cluster; the CrowdStrike LogScale advisory flagged in yesterday's §11 third-pass scan is still pending analyst verification before it enters the tracked list.
- **Thesis-challenge table:** still empty. CVE-2026-33827 (Windows TCP/IP RCE) — now 8 days post-disclosure, still not KEV — remains the closest contender but is product-level, not library.
- **Counter-argument I want to note:** three consecutive days of no KEV additions does NOT validate the HTTP-parsing thesis. The catalog has idle periods; the thesis is about exploitation rates and CWE patterns, not daily additions. Anyone reading the rolling.md should not interpret "quiet KEV days" as "HTTP-parsing CVEs are down." The denominator matters and we only have 22 April data points.

### 13.4 Punch-list (for the HTML editor, not me)

Consolidated from §13.2–§13.3. In priority order:

1. **[~5 min, highest urgency]** Fix dashboard line 160 hero insight. Replace "zero misses" with 3-miss-disclosure language. The dashboard and walkthrough are currently internally inconsistent.
2. **[~10 min]** Update walkthrough §9 intro (line 599) and §9 caveats (line 919) to match §7e's 3-miss disclosure. Consider retitling §9 from "The Zero-Miss Window."
3. **[~15 min]** Add a §7e.5 callout for CVE-2026-34197 as a 2026-04-16 live-fire validation of the CWE-misclassification miss mode.
4. **[~10 min]** Add the manifest-selection-bias paragraph to §7d.
5. **[~5 min]** Add the rebuild-cost-dependency sentence to §10.
6. **[~15 min]** Add the NP+DI-effectiveness KPI tile (16% / 3% / 0%) to the dashboard top row.
7. **[~10 min]** Add a miss-disclosure stat card to the dashboard NP+DI section.
8. **[~5 min]** Add "See also" footers to periodicity.html and cve-reference.html.
9. **[~5 min]** Decide fate of evergreen.html: integrate or mark-as-scratch.
10. **[~15 min]** Consider sidebar-subsection TOC for walkthrough §6 and §7.

Items 1 and 2 are the only must-ship-today changes. Everything else is improvement, not correction.

### 13.5 Overall read

The analysis is stronger than it was 72 hours ago. The 3-miss disclosure paired with the AI safety-net recommendation is the best single piece of intellectual-honesty positioning the project has. The remaining gaps are copy-edits and preemptive disarming of predictable critiques — not structural flaws. If we ship items 1–2 today and items 3–5 within the week, the site reads as a finished argument rather than a work-in-progress.

One caveat to my own review: I'm marking my own homework here — passes 1–3 recommended most of what got built, and now I'm reviewing the result. A fresh external reviewer would probably surface things I'm missing. Worth considering whether to solicit an outside-the-loop reader for a final pass before treating this as "done."

---

*End of review (fourth-pass complete, 2026-04-23).*
