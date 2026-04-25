# Analyst Review — Sixth Pass (2026-04-25)

This is the sixth-pass review of the periodicity analysis and the walkthrough/dashboard restructuring it triggered. It runs against HEAD as of 2026-04-25 morning, ~24 hours after pass 5 closed.

**Important framing note for whoever reads this in isolation:** the brief in `analyst-reports/periodicity-review-brief.md` describes a state of the world that no longer exists. When that brief was written, `docs/index.html` was the original 12-section observational walkthrough and `docs/dashboard.html` had no periodicity content. Both pages have since been restructured around the NP+DI filter — the walkthrough now opens its analytical arc at §6 with the filter, dedicates §7 to cross-framework validation, §8 to OS chaining, §9 to external validation, and §10 to the three-tier model. The dashboard's hero charts are now the cross-framework comparison and the OS privesc accumulation curve. So the question this pass answers is no longer *"how should we restructure?"* — it's *"is the restructuring landed correctly, and what's still broken?"*

This pass is shorter than pass 5 because pass 5's punch list is mostly still the punch list. I'm not going to retype 345 lines of recommendations that haven't been actioned yet. What's new in pass 6:

1. A clean, current-state assessment of the periodicity analysis itself (the brief asked for this and prior passes scattered it across reviews).
2. Devil's-advocate pass — what could still undermine the conclusions.
3. Concrete walkthrough/dashboard delta against the *current* HTML, not the pre-restructure version the brief describes.
4. A cross-page architecture recommendation that takes the "what's the front door?" question seriously.
5. Daily scan: 4 new KEV entries from 2026-04-24 that the refresh agent didn't catch in time, the Mythos breach story, and a 3/3 watch-list KEV-promotion record (up from 2/2 yesterday).

---

## 1. Assessment of the Periodicity Analysis

### 1.1 Is the NP+DI methodology sound?

**Mostly yes, with two structural soft spots.**

What's defensible:

- **The NP/non-NP partition is reproducible.** Every dependency in every manifest is named, classified, and listed. A skeptical reader can rebuild the partition in an afternoon and produce the same numbers. This is the single most important property of a "filter" claim and the analysis nails it. The full CVE reference page (`docs/cve-reference.html`) makes per-CVE classification auditable.
- **The DI CWE set is finite, named, and footnoted.** There are 21 CWEs in the current set (the table in §6b of the walkthrough). That's a small enough number that a reviewer can disagree CWE-by-CWE without having to argue about a black box.
- **The 7-year real-manifest backtest matters more than the 12-month synthetic ones.** That number — 93 C/H → 27 NP+DI → ~24 patch events — is where the filter earns its credibility. The 12-month synthetic stacks are a coverage-of-ecosystems argument; the 7-year manifest is the durability argument. Pass 4 and pass 5 noted this; it's still true.
- **The CWE-misclassification failure mode is honestly disclosed in the 7-year backtest.** Three CVEs (Ghostcat, Tomcat PUT, ActiveMQ Jolokia) reached KEV without the filter flagging them, all because upstream NVD CWE assignments were wrong. The analysis names them, explains the mechanism, and proposes a specific mitigation (an AI safety-net pass that validates CWE assignments against advisory text). That's the correct disclosure posture for a known limitation.

What's structurally soft:

- **NP classification is more judgment-call than the page admits.** Periodicity.html says so explicitly in the caveats — "Reasonable people could draw the line differently" — but several specific calls would lose a face-off in a review. Calling `socket.io` and `passport` NP is fine. Calling `httpclient5` NP-while-treating-`requests`-as-NP-and-`urllib3`-as-NP-but-`pg` (the postgres driver, which absolutely parses network protocol bytes) as non-NP is harder to defend cold. Similarly, `redis`/`ioredis` parse RESP from a network socket and aren't classified NP. The defense is "RESP isn't attacker-controlled" but that's a deployment argument, not a classifier argument. Same with most ORM driver/transport layers. The classifier is doing two things at once and labeling them both "NP": (a) "this component speaks an internet-attacker-reachable wire protocol" and (b) "this component sees attacker-controllable input on its primary code path." Most of the time those collapse to the same answer; when they don't, the filter's behavior is whatever the analyst decided. That's not fatal but it's the place a hostile reviewer would push hardest.
- **Patch-event merging window is 7 days, justified by hand-wave.** "If you're already rebuilding when the next CVE drops, that's one cycle, not two" is true for one-week clusters. For two-week clusters it's also probably true. For 30-day clusters it's not, and the merge window is a knob that materially moves the headline number (especially on 2021's Log4Shell-XStream-jackson cluster). The analysis would be more rigorous with a sensitivity table: 0d / 3d / 7d / 14d merge windows, and the patch-event count for each. The 7-day choice is reasonable; saying "we picked 7 days, here's how the count moves at other windows" is more honest than the current single-number presentation.

Neither of these is fatal. Both should be acknowledged with a sentence-level concession somewhere visible, not buried in caveats.

### 1.2 Is the cross-framework validation convincing?

**Yes, with one important asterisk that's actually working in the analysis's favor and isn't being claimed.**

The 14-14-14 convergence is striking and probably real. Three different ecosystems (Maven, npm, PyPI), three different framework families (Spring/Java, Node/JS, Django/Python), three different sets of maintainers — and each one produces the same all-C/H trigger frequency to one decimal place. If this were a coincidence, you'd expect a much wider spread. The likeliest explanation is the one the analysis hints at: there's a structural rate of C/H disclosures in mature, security-tracked open-source ecosystems that's roughly governed by the size of the dependency tree, and at ~40-50 deps you converge on ~14 dates a year. That's a useful finding in its own right and the analysis doesn't try to claim it.

The asterisk: **all three "synthetic" manifests were authored by the same analyst.** That's the right call methodologically (the manifests need to be representative, not random) but it means the dependency choices reflect one person's mental model of "what's NP." Spring Security being NP, koa being NP, lodash being non-NP — those are defensible choices, but they're not independent of the analyst's hypothesis. The 7-year real-enterprise-Java backtest is the cleaner test because it's a real production manifest the analyst didn't pick. The synthetic stacks are corroborating, not validating.

Currently the walkthrough/periodicity page presents the 12-month synthetic stacks as the "headline" and the 7-year backtest as a supporting case study. That ordering is upside-down for credibility. The strongest test is the 7-year real-manifest result, and it's also the only one with non-zero exploitation evidence to validate against. Lead with it, then say "here's how this generalizes across ecosystems and stacks." Pass 4 §11 made this point; it's still true.

### 1.3 Is the kill chain framing right?

**Right but oversold by half a beat.**

The two-layer model — app layer determines IF (initial access), OS layer determines HOW BAD (blast radius) — is a clean operational story and the data supports the structural finding (the OS layer never produces NP+DI events; LOCAL privesc CVEs accumulate predictably with container age). Monthly container refresh keeping worst-case exposure at 5 vs 21 is a real, useful number.

Where it overreaches:

- **The app→OS chaining argument is implicit, not measured.** The analysis shows that 11 LOCAL privesc CVEs are sitting in the container at the Oct 27 Spring trigger date. It doesn't show that any specific app-layer breach would actually use any specific privesc CVE to escalate. The chained-exploitation framing is a reasonable assumption but it's an assumption. A more careful version would say: "given an app-layer breach yielding code execution as the app user, the container's accumulated LOCAL privesc CVEs are *available for chaining* — whether they actually get used depends on container hardening, kernel version, and the specific CVE's preconditions." Currently the page implies a tighter coupling than it has measured.
- **Container breakout vs in-container privesc is conflated.** The Limitations note acknowledges this — "container breakout (escaping the container to the host) is arguably more impactful and usually requires different vulnerabilities not captured in this OS manifest analysis." That's correct, and it should be promoted from a one-liner footnote to a sentence in the main text. The 21 LOCAL privesc CVEs are mostly in-container escalations from app-user to root-in-container, not breakout-to-host. Most modern attacker workflows from a containerized RCE care much more about lateral movement (other containers, control plane, secrets) than about root-in-container, which they often don't need.
- **systemd's 12 of 21 LOCAL privesc count is keyword noise.** The page acknowledges this. It's worth saying out loud that the *actual* quality of the LOCAL CVE pool is closer to 9-12 real-and-applicable CVEs, with ~3-5 being keyword-search noise. The structural claim survives but the headline number is softer than presented.

None of this kills the argument. The argument is "your container is a chaining substrate, refresh it on a cadence." That's right. The number 21 is doing more work than it should.

### 1.4 Does the external validation hold up?

**The EPSS analysis is genuinely strong work. The "zero-miss" framing on KEV/Metasploit/ExploitDB/Nuclei is still overclaimed.**

The EPSS section is the best piece of analysis in the periodicity page. The Day 0 / Day 7 / Day 30 / Eventually table is exactly the right way to present a real-time triage filter against a retrospective scoring system, and the conclusion ("EPSS catches what broken CWE metadata hides from NP+DI; NP+DI fires before EPSS has signal; they're complementary not redundant") is a defensible, useful answer to "should I just use EPSS?" That's the section a CISO will quote.

The KEV/Metasploit/ExploitDB/Nuclei sections are weaker on their own merits, and the page is mostly honest about why ("KEV is overwhelmingly product-focused, not library-focused. Only ~3.8% of KEV entries are library-level. The absence of our CVEs from KEV says more about KEV's coverage than about the filter's accuracy."). That's the right disclaimer. The problem is that the same page then concludes with "zero misses across 113 non-trigger CVEs" as the headline.

This is the issue pass 4 §13.2 raised, pass 5 §1.2 elevated to "highest urgency, must-ship-today, ~5 min copy edit," and which remains unfixed in:

- `docs/dashboard.html` line 161 (hero copy): "with zero misses — no filtered-out CVE has appeared in CISA KEV"
- `docs/index.html` line 177 (TL;DR): "with zero misses in 12 months"
- `docs/index.html` line 600: "Zero misses across 113 non-triggers"
- `docs/index.html` line 686: "should produce zero misses"
- `docs/periodicity.html` line 541, line 685

The 7-year backtest in walkthrough §7g openly admits 3 misses (CWE-misclassification cases). The dashboard hero, walkthrough TL;DR, and periodicity conclusion all say "zero misses" without that qualification. That contradiction is internally inconsistent and a hostile reader will land on the inconsistency, not the disclosure.

This is a copy edit, not an analysis change. It is the most cost-effective edit available to the project and it has been on the punch list for two passes. **Do it.**

### 1.5 Devil's advocate — what could undermine the conclusions

I'm being asked to play this role explicitly, so:

**1. Survivorship bias in the 7-year backtest.** The "real Java manifest" being analyzed is presumably a manifest from a portfolio of currently-running Spring apps. By definition, those apps survived 7 years of operation without a catastrophic breach via something the NP+DI filter would have missed. If they had been breached via a non-NP/non-DI CWE, those apps probably wouldn't be in the manifest the analyst chose to backtest. This is the standard problem with backtesting any triage policy against survivors. The fix is forward validation, which the dashboard gestures at but doesn't formalize.

**2. KEV is government-and-enterprise biased.** Pass 5 said this; the periodicity page acknowledges it. But the "zero-miss" framing assumes KEV is the ground truth for "what got exploited." Bug-bounty-monetized exploitation, criminal-marketplace exploitation of npm packages, and supply-chain compromises (which OSV captures but KEV mostly doesn't) are all systematically undercounted in KEV. A library CVE that got exploited in 50 npm-supply-chain attacks but never showed up in a CISA report is a "miss" the filter would never know about. The fix is to also validate against OSV-flagged exploited (the project already has an `osv-exploitation.html` scratch page; it should feed back into validation).

**3. The DI CWE set is now versioned and was widened twice in two weeks.** Pass 5 §1.1 covered this in detail. Briefly: the set started smaller, gained CWE-444 after one round of review, then gained CWE-287/289/306/345/693/863/1321 in the auth-bypass widening on 2026-04-23. Both widenings are individually defensible. The cumulative effect is that the filter now flags ~5 events the original filter missed, which conveniently turn ~73% reduction into ~67% reduction *and* preserve the zero-miss claim. Without a public CWE-set changelog, this looks exactly like p-hacking. The data isn't p-hacked. The presentation is.

**4. The 12-month synthetic-stack window started 2025-04 and ended 2026-04.** That window is bracketed by the Mythos Preview announcement (2026-04-07). The April 2026 spike in Spring (8 events vs 14 in the prior 11 months combined, all in network parsers, 6 of 8 DI) is exactly the pattern you'd expect if AI-assisted code review is suddenly dumping months of accumulated findings on the most exposed dep tier. The analysis correctly identifies this as "April was anomalous." But: if April-2026 represents the *new* baseline rather than an anomaly, then the headline number "Spring 64% reduction" is partly an artifact of the pre-Mythos period being unusually quiet on the parsing front. The forward-validation question — "what does the filter look like in 2026-Q3 and Q4 against post-Mythos volume?" — is the actual test. The dashboard should call this out as the live experiment, not a footnote.

**5. The OS-layer NP+DI=0 result is partly a definitional artifact.** The OS-layer manifest excludes the kernel (correctly — it's a separate patch domain). It also excludes container runtime, kubelet, the CNI plugin, the CSI driver — all the components that *would* be most likely to produce NP+DI events at the OS layer. The 25-component OS manifest is a fair representation of an Amazon Linux 2023 base image, but it's not a fair representation of the production attack surface a Spring app actually runs on. A Kubernetes pod sees the kubelet's HTTP API; that's an NP+DI surface that the analysis doesn't model. This is acknowledged in passing ("doesn't represent the full post-exploitation picture") but the structural conclusion "OS layer never produces NP+DI events" is stronger than the evidence supports. The honest version is "the OS *base image* layer, narrowly scoped to glibc/systemd/userland libs, doesn't produce NP+DI events; the orchestration and container-runtime layers above it are out of scope and would likely produce some."

**6. The "burst not drip" framing is over-rotated on a small sample.** Five events in Spring across 12 months is enough to say "they cluster" — there are two clusters (Oct 2025, April 2026), separated by a long gap. But two clusters on five events is not a strong distribution claim. It's consistent with "bursty," it's also consistent with "uniform with bad luck." The 7-year backtest does support burstiness more strongly (Log4Shell cluster, XStream cluster, Spring4Shell cluster). Lead with the 7-year evidence for the burst pattern; treat the 12-month synthetic stacks as illustration.

None of these kill the analysis. Several of them sharpen it.

---

## 2. Walkthrough Restructuring — Status of the Restructure That Already Happened

The brief asked for a section outline. The walkthrough has *already been re-outlined* and most of the brief's recommendations are landed. The current §1-§14 structure is:

1. The Problem
2. Methodology
3. The First Clue: Where Exploits Actually Land (3a/b/c — layer rates, NP/non-NP, library denominator)
4. Why Most Criticals Don't Get Exploited
5. Time-to-Exploit Compression
6. **From Observation to Filter: NP+DI** *(new — covers 6a/6b/6c)*
7. **Does It Actually Work? Cross-Framework Validation** *(new — 7a–7g, including the 7-year manifest backtest)*
8. **Land & Expand: The Exploit After the Exploit** *(new — kill chain framing)*
9. **External Validation: The Zero-Miss Window** *(new — EPSS + KEV/MSF/EDB/Nuclei)*
10. **Putting It Together: The Three-Tier Patching Model** *(new — Tier 1/2/3 + WAF Dividend)*
11. The Reverse Proxy Myth
12. Mythos Detector: Will AI Break the CVE Firehose?
13. Exploit Watch List
14. Caveats & Methodology Limitations (with periodicity-specific section)

This is the right structure. The narrative arc — observation (§3-§5) → filter formulation (§6) → cross-stack test (§7) → blast-radius extension (§8) → external cross-checks (§9) → operational synthesis (§10) — is exactly the prescriptive arc the brief was asking for. Section 9's old patch-SLA-by-CVSS framework is gone; the new §10 three-tier model replaces it. That was the most important single substitution and it's done.

What's still wrong with the walkthrough:

### 2.1 The §9 title and TL;DR overclaim (highest priority — copy edit only)

Carry the §1.4 fix through:
- §9 title: "External Validation: The Zero-Miss Window" → **"External Validation: Cross-Checking the Filter Against Five Exploitation Databases"**
- TL;DR (line 177): "with zero misses in 12 months" → **"with no exploited CVE missed in the 12-month synthetic backtest. The 7-year real-manifest backtest found 3 misses, all traceable to NVD CWE misassignment and addressable by an automated CWE-validation pass (§7g)."**
- §9 line 600: "Zero misses across 113 non-triggers" → **"No non-trigger CVE accumulated meaningful exploitation evidence (KEV / Metasploit / ExploitDB / Nuclei) within the 12-month window."**
- §10 line 686: "should produce zero misses" → **"should approach zero exploitation misses; track CWE-classification disagreements as the leading indicator of the misclassification failure mode."**

These are the same bullets pass 5 §1.2 listed. They are still right. They are still the cheapest credibility win available.

### 2.2 §6 is missing the CWE-set versioning callout

Pass 3 and pass 5 both asked for a §6d (CWE Set Versioning & Changelog). Still not there. The page lists 21 CWEs with a footnote about CWE-444 being added "after external review" but no changelog. The auth-bypass widening (CWE-287/289/306/345/693/863/1321) added 2026-04-23 isn't disclosed at all in the walkthrough — only in `data/di-reclassification.json` and the global CLAUDE.md notes.

Recommended new §6d, ~half a page:

> **6d. CWE Set Versioning**
>
> The DI CWE set is versioned. New CWEs are added when review identifies them as genuine network-parser direct-injection patterns. Each change is dated, justified in the data file [`data/di-reclassification.json`], and the validation backtest is re-run.
>
> | Version | Date | Change | Backtest delta |
> |---|---|---|---|
> | 1.0 | 2026-04-21 | Initial set: 13 CWEs (78, 77, 22, 23, 36, 94, 95, 89, 918, 917, 1336, 116, 74) | 12mo synthetic: 16 events |
> | 1.1 | 2026-04-22 | + CWE-444 (request smuggling) — added after Netty backtest produced zero events without it | +1 event (Netty Mar 26) |
> | 1.2 | 2026-04-23 | + CWE-287, 289, 306, 345, 693, 863, 1321 (auth bypass via input manipulation) | +4 events (Spring +3, Django +1) |
>
> Future widenings will be appended to this table. The set is not closed; new injection patterns may justify additions. Consensus criteria: (a) attacker input changes a security-relevant decision in the parser, (b) at least one historical CVE with this CWE has reached KEV via the network-facing surface, (c) addition must be justified before the backtest is rerun, not after the new event is observed.

That last criterion is the goalpost-moving prophylactic. Without it, the changelog is just disclosure; with it, it's a precommitment.

### 2.3 §7g (the 7-year backtest) should be promoted to §7's headline

Currently the structure is: 7a-7f present the 12-month synthetic stacks, 7g is "Real-World Case Study: Enterprise Java Portfolio." The 7-year manifest is the strongest piece of evidence in the document (longest window, real production manifest, 5 confirmed-exploited CVEs to validate against). Burying it as a "case study" at the end of §7 is inverted hierarchy.

Reorder §7:

- 7a. **Real-World Case Study: 7 Years of Enterprise Java** (move 7g here — lead with the strongest test)
- 7b. Generalizing Across Ecosystems: Three Synthetic Stacks (12 months) (was 7a)
- 7c. The 14-14-14 Convergence (was 7b)
- 7d. Reduction by Stack (was 7c)
- 7e. Silence Windows (was 7d — keep)
- 7f. What the Filter Caught (was 7e — keep)
- 7g. Django: The Honest Hardest Case (was 7f — keep)

Rationale: the 7-year backtest does what the synthetic stacks can't — it has actual exploited CVEs to test against. The synthetic stacks have zero KEV hits (which is partly informative, partly an artifact of KEV's library coverage). Leading with the strong test, then showing the cross-ecosystem generalization, is the right rhetorical order.

### 2.4 §8 (kill chain) needs the breakout-vs-privesc distinction surfaced

Currently §8 jumps from "Spring trigger dates" to "21 LOCAL privesc CVEs available" without distinguishing in-container escalation (root in container) from breakout (escape to host). Both are useful but they have different operational implications. Add one sentence:

> **The 21 LOCAL CVEs here are in-container privesc — escalating from app-user to root within the container. Container breakout (escape to host) requires different vulnerabilities — kernel bugs, container runtime flaws — not captured in this OS manifest. The blast-radius argument here is about lateral movement and data access within the cluster, not full host compromise.**

### 2.5 §10 (three-tier model) is correctly placed but should land harder on Tier 2

Tier 2 (monthly container refresh) is the most under-explained part of the model. Tier 1 has a clear trigger (NP+DI fires). Tier 3 has a clear cadence (whatever your normal release rhythm is). Tier 2 says "monthly" but the *justification* for monthly specifically — "going to bi-weekly only saves one more CVE" — is mentioned in the periodicity page but not the walkthrough. Lift that into §10.

### 2.6 §11 (Reverse Proxy Myth) is stale and probably should move

Reverse-proxy-isn't-a-shield is a real point, but it sits between §10 (three-tier model — the operational synthesis) and §12 (Mythos Detector — the forward-looking watch). It interrupts the narrative arc. Either move it earlier (right after §3 with the layer breakdown — it's a layer-misconception correction) or fold it into §14 caveats.

### 2.7 §14 caveats should grow a "Limits of This Backtest" subsection

Pull together what's currently scattered:
- KEV's enterprise-product bias
- 7-day patch-event-merge window is a knob
- NP classification is judgment-call
- 12-month window straddles the Mythos announcement
- OS-layer scope excludes orchestration / runtime / kernel

A reader who reaches §14 has earned the honest version. Currently the honest version is dispersed.

### 2.8 Should periodicity.html be folded in?

**No, keep it separate.** Two reasons:

1. The walkthrough is the *story*. The periodicity page is the *workbook* — it has the full per-CVE tables, the EPSS day-0/day-7 timeline, the manifest-by-manifest comparison, the validation database cross-references. Two different audiences. The walkthrough wants a CISO/lead-engineer who has 15 minutes; the periodicity page wants a security architect who has an hour and wants to push back on specific classifications.
2. Folding 900 lines of HTML into the already-1273-line walkthrough would push the walkthrough past 2000 lines and make the narrative arc unreadable. The current architecture (walkthrough = narrative; periodicity = workbook; cve-reference = data; dashboard = live state) is correct.

What *should* change is the cross-linking. Walkthrough §7 should link out to periodicity.html for "the full manifest tables" rather than re-presenting summaries. Periodicity.html should link back to walkthrough §6 and §10 rather than recapping the filter and the three-tier model in its own conclusion. Currently both pages partially recap each other; that's where the maintenance burden comes from.

---

## 3. Dashboard Updates

Current dashboard (post-restructure) opens with:
- KPI cards
- Cross-Framework: All C/H Dates vs NP+DI Dates
- OS Container Privesc Accumulation
- EPSS Exploitation Probability
- Then the original layer-rate / parser-vs-non-parser / lift / TTE charts
- Three-tier model card (Tier 1/2/3)
- Watch list, thesis challenge

This is mostly the right ordering. Specific changes:

### 3.1 Hero copy (line 161) — fix the zero-miss overclaim

Same edit as §2.1. Currently the dashboard opens with "reduces rebuild-trigger dates by 64–86% with zero misses — no filtered-out CVE has appeared in CISA KEV." The dashboard's *own* OS-layer chart lower on the page shows the zlib KEV hit. The hero contradicts what the page itself shows further down. Fix:

> **Reduces rebuild-trigger dates by 64–86% across three ecosystems. No app-layer non-trigger CVE in the 12-month window accumulated significant exploitation evidence (KEV / Metasploit / ExploitDB / Nuclei). Three historical misses across 7 years of backtest were CWE-classification failures, addressable by an automated CWE-validation pass.**

### 3.2 Add a CWE-set version badge near the cross-framework chart

A tiny "DI CWE set v1.2 (2026-04-23)" badge with a tooltip that says "CWE set is versioned; 21 CWEs current. See walkthrough §6d for changelog." This is the simplest disclosure that addresses the goalpost-moving criticism without requiring a full UI rebuild.

### 3.3 Add the 7-year backtest as a chart, not just a number

The 7-year manifest analysis is in the periodicity page only. It should have a presence on the dashboard — even just a stacked bar chart of "All C/H per year" vs "NP+DI per year" with KEV/MSF dots. This is the strongest single piece of evidence in the project and the dashboard barely shows it.

### 3.4 Watch-list KEV-promotion record should be a hero KPI

As of this morning, three watch-list entries have been promoted to KEV in the past four days: CVE-2026-33825 (Defender BlueHammer, 2026-04-22), CVE-2026-39987 (Marimo, 2026-04-23), and CVE-2024-7399 (Samsung MagicINFO, 2026-04-24 — see daily scan §5 below). This is a 3-for-3 prospective hit rate. Pass 5 §3 said it should be a hero stat at 2-for-2; it's now 3-for-3 and still isn't on the dashboard.

Add a KPI tile: "**Watch-list → KEV promotions: 3/3 in 96 hours.**" With the three CVEs and the original watch-list dates underneath.

### 3.5 The Glasswing-extracted nav looks correct

`docs/glasswing.html` exists, is labeled "Intelligence Assessment — speculative analysis," and the nav bar on all five pages includes a Glasswing tab. Pass 5 already commended this. Good.

---

## 4. Cross-Page Architecture

There are now five HTML pages and they each want to do something different. Currently they cross-link inconsistently. Recommended architecture:

| Page | Audience | Purpose | First-screen promise |
|---|---|---|---|
| **dashboard.html** | CISO / lead eng with 2 min | Live state + headline numbers | "Here's the filter, here's how it's doing this week" |
| **index.html (walkthrough)** | Lead eng / arch with 15 min | The argument, end-to-end | "Here's why network-parser direct-injection is the right filter and how to operationalize it" |
| **periodicity.html** | Sec arch with 1 hour | The workbook — every test, every manifest | "Here are the 129 CVEs we tested against, here's what we did with each one" |
| **cve-reference.html** | Anyone challenging a specific call | Data table | "Find any CVE, see why we did or didn't flag it" |
| **glasswing.html** | Anyone who wants the Mythos angle | Speculative intelligence assessment | "Here's what the Mythos rollout might do to the filter, with all the caveats" |

### 4.1 The front door problem

A new reader hitting `funwithscience-org.github.io/KEV-analysis` lands on `index.html` (the walkthrough). That's correct — the walkthrough is the story. But the walkthrough opens with §1 "The Problem" before the reader knows what they're looking at. The first screen should answer: *what is this site, who is it for, what's the headline finding?*

Recommend a new pre-§1 hero block on the walkthrough:

> **CVE Exploitation Analysis** — A New Way of Prioritizing Vulnerabilities
>
> An empirical study of which CVEs actually get exploited, what distinguishes them from the >99% that don't, and how to use that distinction to cut emergency rebuild events by ~70% across three different framework ecosystems and 7 years of real production data.
>
> [→ Live dashboard]   [→ Full CVE reference]   [→ Methodology workbook]

That's a 6-second pitch. The current opening goes straight to "every infosec team... 250+ critical CVEs every month" which is a real problem, but it doesn't tell the reader they're about to read the answer.

### 4.2 Inter-page nav

Currently the top-of-page nav on all five pages has: `Walkthrough | Dashboard | Periodicity Analysis | CVE Reference | Glasswing`. That's right but the labels are inconsistent — "Walkthrough" reads as "the explanation," "Periodicity Analysis" reads as the title of a paper, "CVE Reference" reads as a table. Standardize the verb form:

`Argument | Live State | Workbook | Data | Intelligence`

Or keep them descriptive but match register:

`The Walkthrough | The Dashboard | The Workbook | The Data | The Mythos Watch`

The current labels are workable, just slightly mismatched. Lower priority than the §2.1 zero-miss copy edit.

### 4.3 Stop both pages from recapping the filter

The walkthrough's §6 defines NP+DI. The periodicity page also defines NP+DI in its own section. When the filter changes (CWE-set version bump, NP-classification edge case, etc.), both pages need to be updated and they drift. Pick a canonical location and have the other page link to it.

Recommend: **the walkthrough §6 is canonical.** Periodicity.html removes its own "what is NP+DI" section and replaces it with a one-paragraph summary plus a "see walkthrough §6 for the full filter definition" link. This eliminates one drift surface.

The CVE reference page has its own filter definition near the top; same fix — short summary, link to canonical.

---

## 5. Daily Scan — 2026-04-25

### 5.1 New KEV entries the refresh agent didn't catch

CISA published catalog version 2026.04.24 yesterday (2026-04-24, after the 2026.04.23 version that the refresh agent picked up). Four new entries:

| CVE | Vendor / Product | CWE Class | NP+DI? |
|---|---|---|---|
| CVE-2024-7399 | Samsung MagicINFO 9 Server | Path Traversal (CWE-22) | **YES** — NP + DI |
| CVE-2024-57726 | SimpleHelp | Missing Authorization (CWE-862/863-adjacent) | **YES under DI v1.2** — auth bypass |
| CVE-2024-57728 | SimpleHelp | Path Traversal (CWE-22) | **YES** — NP + DI |
| CVE-2025-29635 | D-Link DIR-823X | Command Injection (CWE-77) | NP+DI but **out of scope** — network device firmware |

The refresh agent (`kev-tracking.json` line 18) still has `count: 24` and `catalog_version: "2026.04.23"`. The 2026-04-24 catalog update isn't reflected. Refresh agent should pick this up on the next run.

**Significance:** three of the four new KEV entries are HTTP-parsing-adjacent direct-injection bugs in web management interfaces — exactly the NP+DI signature. The fourth (D-Link) is network-device firmware and out of the project's stated scope (HTTP-parsing attack surface in apps and frameworks, not network device firmware). This is more confirmation of the pattern, not a challenge to it.

**Watch-list cross-check:** SimpleHelp wasn't on our server-side watch list. It probably should be — RMM/remote-support tools with web management interfaces have appeared in KEV repeatedly (Kaseya, ConnectWise ScreenConnect). Recommend adding SimpleHelp to the server-side watch list with rationale "RMM web-admin parsing surface." Samsung MagicINFO is digital-signage-specific and probably not worth adding.

### 5.2 Watch-list → KEV promotion record now 3/3 in 96 hours

Tracking the watch-list prospective accuracy:
- 2026-04-22: CVE-2026-33825 (Defender BlueHammer LPE) → KEV. Was on desktop watch list with `weaponized` maturity.
- 2026-04-23: CVE-2026-39987 (Marimo pre-auth RCE) → KEV. Was on server-side watch list.
- 2026-04-24: CVE-2024-7399 (Samsung MagicINFO path traversal) → KEV. **Not** on the watch list.

So strictly speaking the streak is 2/2 hits on watch-list-flagged items, plus 1 KEV addition that wasn't watch-listed. The 3/3 framing is technically wrong; correct framing is **2 of 2 watch-listed CVEs that got promoted in the last 96 hours, with a third HTTP-parsing-adjacent KEV addition the watch list missed.**

Correction to pass 5 §3: the framing should be "2/2 watch-listed CVEs that have been promoted to KEV in 4 days" — that's still a strong number, but it's not 3/3 because Samsung MagicINFO wasn't on the list. The miss matters as much as the hits — it suggests the watch list is too tightly scoped to widely-deployed-mainstream tools and is missing mid-tier RMM and digital-signage gear.

### 5.3 Mythos breach — context, no action needed

WebSearch surfaced two new pieces of Mythos-adjacent news that weren't in the prior tracking file:

- **2026-04-21: Anthropic confirmed unauthorized access to Mythos Preview** via a third-party vendor environment. Discord-linked group exploited shared contractor accounts and API keys. (rankiteo.com, letsdatascience.com coverage)
- **2026-04-22: Foreign Policy long-form on Claude Mythos's strategic implications.** Not new technical info; useful as evidence that the Mythos rollout is now a top-tier policy story, which means the volume / capability question the walkthrough §12 raises is going to get more public scrutiny.

**Relevance to the project:** the breach doesn't change anything in the analysis (Mythos Preview isn't in production yet, no leaked Mythos-discovered CVEs have appeared in disclosure feeds), but it does tighten the timeline pressure on participant vendors. If preview-era findings can leak via a Discord group exploiting contractor creds, the "preview is the buffer" framing of the walkthrough §12 is weaker than it was a week ago. Worth a sentence in §12: "Anthropic confirmed unauthorized access to Mythos Preview on 2026-04-21 via a third-party vendor environment. The preview-era buffer is no longer hermetic; participant vendors should assume their pre-public findings are at higher leak risk than originally framed."

### 5.4 NVD volume update

April 2026 NVD MTD: 5,037 (day 25 of 30, +66 net over the prior 24h). Extrapolation: 6,044 for the month. That's lower than the day-24 extrapolation (6,214) because today's pub rate (66/day) was well below the running April average (~200/day). Saturday-of-final-week is unremarkably low. April will land in the 6,000–6,200 range, consistent with the Q1 2026 churn band (4,808–6,304) and providing no positive evidence of a Glasswing-driven volume shock. The Mythos-volume-explosion thesis still has no observational support; the volume signal is firmly in the null.

### 5.5 Glasswing CVE count

Total Glasswing-attributable CVEs: 283 (271 Mozilla Firefox, 9 wolfSSL, 1 each F5 NGINX Plus, FreeBSD, OpenSSL). No new Claude-credited CVEs in the past 24h. The Firefox 150 / MFSA 2026-30 batch is still the dominant chunk. AISLE blog notes 5 of 7 OpenSSL April 2026 CVEs were AI-uncovered, consistent with prior runs.

No participant-vendor disclosures cross-referenced against today's KEV additions; SimpleHelp and Samsung MagicINFO are not Glasswing participants. D-Link is not a Glasswing participant.

### 5.6 Items for follow-up

- **Refresh agent should reconcile against catalog version 2026.04.24** on its next run. The 4 new entries above need to land in `kev-tracking.json`.
- **Add SimpleHelp to server-side watch list** with rationale "RMM web-admin parsing surface; multi-CVE cluster reaching KEV 2026-04-24."
- **Update §12 of the walkthrough** with the Mythos breach disclosure (one sentence; don't blow it up into a section).
- **The five copy edits in §1.4 / §2.1 of this report** (the zero-miss overclaim) remain the highest-leverage edit available and have been on the punch list for two passes. Whoever next touches the HTML files: do these first.

---

## 6. Punch List — Carry-Forward + New

Carrying forward from pass 5 (still open):

1. ☐ Fix zero-miss overclaim in dashboard hero, walkthrough TL;DR, walkthrough §9, walkthrough §10, periodicity conclusion (5 lines, ~10 min)
2. ☐ Add walkthrough §6d "CWE Set Versioning & Changelog" (~30 min)
3. ☐ Add `tests/test_kev_classifier.py` with ~20 canonical examples (~45 min)
4. ☐ Triage the `other` bucket in `data/kev-layer-classifications.json` (~1 hr)
5. ☐ Reorder §7 to lead with the 7-year manifest backtest (~30 min)
6. ☐ Add CWE-set version badge to dashboard near cross-framework chart (~15 min)

New from this pass:

7. ☐ Add 7-year backtest chart to dashboard (~45 min)
8. ☐ Add patch-event-merge-window sensitivity table to periodicity.html (~30 min)
9. ☐ Promote breakout-vs-privesc distinction in walkthrough §8 (~15 min)
10. ☐ Add Mythos breach disclosure to walkthrough §12 (~10 min)
11. ☐ Add SimpleHelp to server-side watch list (~15 min)
12. ☐ Add hero KPI tile to dashboard for watch-list KEV-promotion record (correctly framed as 2/2 watch-listed, not 3/3 KEV-additions) (~30 min)
13. ☐ Fold §6 NP+DI definition canonically into walkthrough; trim periodicity.html and cve-reference.html to summary-plus-link (~1 hr)
14. ☐ Pre-§1 hero block on walkthrough with 6-second pitch + cross-page nav cards (~45 min)

Total estimated time to clear current punch list: roughly 6 working hours, of which the highest-leverage 90 minutes are items 1, 2, 6, and 10.

---

## 7. Bottom line

The periodicity analysis is genuinely strong work. The 7-year real-manifest backtest with 5 confirmed-exploited CVEs caught and 3 disclosed CWE-misclassification misses is a credible empirical result. The cross-ecosystem 14-14-14 convergence is striking. The EPSS comparison is the best section in the project. The three-tier patching model is the right operational synthesis.

What's been holding the project back from a stronger external posture isn't the analysis — it's the presentation. The dashboard hero, walkthrough TL;DR, and periodicity conclusion all still claim "zero misses" without the qualifier the body of the work itself adds. Two CWE-set widenings have happened in two weeks without a public changelog. The 7-year backtest, which is the strongest evidence in the project, is currently labeled "case study" and buried at the end of §7. The watch-list KEV-promotion record (a real prospective-validation win) isn't on the dashboard.

These are all copy/structure issues, not analysis issues. None of them require new data work. Most of them are 15-30 minute edits. Doing them clears the gap between the strength of the underlying analysis and the way it's being presented.

— pass 6 / 2026-04-25
