# Periodicity Analysis & Walkthrough Restructuring — Analyst Review

**Date:** 2026-05-03
**Author:** kev-analyst (scheduled)
**Scope:** Assess `docs/periodicity.html` and recommend changes to `docs/index.html`, `docs/dashboard.html`, and the cross-page architecture.

---

## 0. Up-front: the brief is partly stale

The review brief (`analyst-reports/periodicity-review-brief.md`) describes a walkthrough still organized around the *observational* HTTP-parsing thesis, with §9 still proposing CVSS-based SLAs. **That is no longer the state of `docs/index.html`.** The walkthrough has already been restructured around the *threat-based prioritization model* — TL;DR card up top, the model itself in §3 (NP+DI structure test + hacker discriminator), 12-month cross-framework validation in §4, the 7-year backtest with the 10/11 union catch in §4f, EPSS comparison in §8, and an estate-maturity (Cat 1/2/3) operational model in §9.

So the right question is no longer "how should we restructure this from scratch?" but "what's still loose, what's now redundant, and where does the periodicity page itself need editing?" That's what the rest of this report does. Where the brief asked for "restructure x," I've translated to "tighten / cut / reorder x" against the current state.

---

## 1. Assessment of the Periodicity Analysis

### What works

1. **The structure-test / attacker-test split is the right framing.** The page treats NP+DI and hacker S+A as two independent operationalizations of the same underlying claim and scores them side-by-side. That makes the result robust to either method's biases — the union catches 10/11 even though each method alone misses 2-3. This is exactly the kind of cross-method triangulation a reviewer would ask for.

2. **The 7-year backtest is the discrimination story; the 12-month synthetic stacks are workload only.** The page now says this loudly and repeatedly — it used to conflate them. The "N=1 means zero-misses is operationally vacuous" caveat is the right honesty bar and it's reproduced in roughly the right places (§3 hero callout, §4f, §13 caveats). Good.

3. **The Tomcat HTTP PUT 2017 worked example is the strongest single move on the page.** It takes the only event the union doesn't catch directly and shows — with timeline — that the four-year disclosure-to-KEV gap was filled by six unrelated NP+DI Tomcat rebuilds. The "B-tier handled by supplements" claim is no longer hand-waved; it's evidenced. This is the part of the analysis that will survive an external curmudgeon.

4. **The EPSS comparison is decisive and honest.** "EPSS catches 8/8 eventually but 1/8 on day 1" is the comparison that actually matters operationally, and the marginal-cost table (3 events of EPSS-50 work on top of NP+DI; 1 on top of NP+DI+DQ) reframes EPSS from competitor to thin backstop. The pre-EPSS exclusion (Ghostcat/Tomcat-CGI from the days-faster mean) is exactly the right move — it keeps the headline credible.

5. **The OS NVD-noise cleanup is a serious correction.** The acknowledgement that 50 of 69 "OS layer" CVEs are downstream-app keyword matches (sqlite-using apps, kernel-via-systemd, snapd-not-in-AL2023) is the kind of finding most projects bury. The site reports it in both periodicity.html §14 and walkthrough §7. The cleaned 10-12 LPE / ~70% reduction figure is more defensible than the raw 21 / 76%.

### What I'd push back on

1. **"Zero misses across 113 non-trigger CVEs" still leaks into the prose even with the caveat.** §15 conclusion still has "The 12-month synthetic stacks have zero misses" as a hero statement, and only the next sentence backs off to "the 7-year real manifest tells a more honest story." A skeptical reader skims headlines. Recommend either (a) hard-cut the "zero misses" hero claim and lead with the 7-year 10/11 number, or (b) collapse the two paragraphs into one that opens "On 7 years of real production data, the union of structure + attacker tests catches 10 of 11 directly; on the 12-month synthetic window, every strategy catches the one in-scope exploit, which is a workload claim, not a discrimination claim."

2. **The "leading indicator" framing in §15 is the weakest single sentence on the page.** "The filter may actually be a leading indicator — identifying CVEs that will accumulate exploitation evidence over the next 6-18 months" is an unfalsifiable promise. The only evidence cited (Django SQLi reaching ExploitDB) is one CVE. Either drop this paragraph or replace it with the freeze-counter framing: "We've frozen the DI CWE set as of 2026-05-01. From now forward, every confirmed-exploited CVE either fires under one of the discriminators or is logged as a public miss. That track record is the leading-indicator test." The dashboard already has this counter. The page should reference it as the operational answer to the leading-indicator claim.

3. **Manifest-scope generalization is asserted but not validated cross-ecosystem.** The dashboard does say "Java-specific until parallel 7-year backtests on Node/Django/Netty are published" (yellow callout). The periodicity page does not. The §9 Cross-Ecosystem Pattern reads like the four 12-month manifests *are* the cross-ecosystem proof — they're not; the 12-month manifests are workload-only by the page's own admission. The cross-ecosystem *discrimination* claim rests on one ecosystem's 7-year backtest. Recommend a one-sentence honesty note in §9 mirroring the dashboard's yellow callout.

4. **The chart at §4 (`crossFrameworkChart`) is mislabeled in the data behind it.** The "All C/H trigger dates" bar is 14/14/14/3 — but the page's own §3 callout says "Spring 5, Node 1, Django 4, Netty 1" for hacker S+A. The chart shows "Spring 5, Node 3, Django 4, Netty 1" for hacker S+A, while the headline text says Node = 1. There's a Node = 1 vs Node = 3 conflict between the §3 narrative and the §4 chart/table. The §4 table itself is internally consistent (Node = 3 hacker / 2 NP+DI / 4 NP+DI+DQ); the §3 hero stat needs to match. Fix one of them.

5. **The "Hacker S+A on the OS layer agrees: zero S, zero unconditional A — and most of the '48 NETWORK' events are NVD keyword noise" callout in §14 is doing too much work in one paragraph.** It introduces a methodology change (NVD keyword cleanup), restates the NP+DI = 0 result, and pivots the rationale for monthly container refresh from "21 LPE → 5" to "10-12 LPE → 2-3." Each of those is a separate point and the reader has to assemble them. Recommend splitting into three short paragraphs with the cleaned numbers in a small table.

6. **Devil's advocate, hardest hit:** the canonical 58-package manifest is *one Java enterprise dependency list*. The paper's central effectiveness claim (10/11 catch on disclosure day) rests on it. A skeptical reviewer will ask: how was this manifest assembled? Is it a real production list from a real organization, or a curated example? If curated, what's the protocol for inclusion/exclusion that prevents post-hoc selection? The page says "real enterprise Java manifest" but doesn't sketch the provenance. Even one paragraph — "this manifest comes from [class of org]; inclusion criteria were [X]; we excluded [Y categories]; the manifest was frozen on [date]" — would defang a lot of curmudgeon energy. Right now the canonical manifest is a strong claim with a soft pedigree.

7. **The "deserialization is dead" finding (§11) is overstated.** "Deserialization is a CVE volume generator (historically), not an exploitation driver" is true on the 12-month window for these manifests, but the 7-year backtest's exploited cohort includes Text4Shell (CWE-94, but a string-interpolation/template-injection adjacent to deser cousins) and SnakeYAML 2022-1471 (CWE-502). The hacker rubric catches both; the structural rule excludes them at the package level. So the framing "deserialization is mostly noise" is correct on volume but the hacker test had to do real work to recover the two events the structure test missed in the gadget-chain space. Worth a sentence.

8. **The "April 2026 spike" speculation about Mythos (§12) is risky.** Anthropic does not directly find or disclose CVEs on vendors' codebases — vendors scan their own code with Mythos Preview. The page's framing ("The timing is suggestive: Anthropic announced Glasswing/Mythos on April 7. The Tomcat batch (7 CVEs) dropped April 9 — a coordinated release pattern consistent with accumulated findings") is suggestive without evidence. The Cisco-ISE/Webex precedent (probable participant, then confirmed *not* Mythos but OpenAI Codex) is a cautionary tale we already learned. Recommend softening to "We can't attribute these batches to Mythos; the timing alignment is interesting and worth flagging for forward observation."

### Methodology gaps I noticed

- The `compute_epss_marginal.py` methodology in §15 says EPSS crossing dates are approximated from FIRST.org probes at offsets `{1, 3, 7, 14, 30, 60, 90, ...}` with the note "conservative (over-credits absorption when the true crossing falls between two probes)." That's the right direction (over-credit absorption favors the structure test in the marginal-cost framing). Worth a one-line "this asymmetry favors the model and is acknowledged."

- The page never quantifies the WAF "MEDIUM" category's actual time-to-bypass on the historical events. It tags 7/13 events as MEDIUM and asserts "evadable" — a paragraph naming one or two specific bypasses (the Log4j Unicode-escape evasion is an obvious example) would convert the assertion to evidence.

- The Hacker S+A vs NP+DI agreement-disagreement table (§4 / §7) lists divergences but doesn't have a single matrix view. A 2×2 (caught-by-hacker / not-caught-by-hacker × caught-by-NPDI+DQ / not) for the 11 exploited events would make the union calculation auditable in one glance. Right now the reader has to chase the events through two tables.

---

## 2. Walkthrough Restructuring Recommendations

The walkthrough is much closer to the right structure than the brief implied. The current order is:

```
TL;DR → §1 Problem → §2 First Clue (observational) → §3 The Model →
§4 Cross-Framework Validation (incl. 7-year backtest in §4f) →
§5 Why most criticals don't get exploited → §6 Time-to-Exploit →
§7 Land & Expand (kill chain) → §8 External Validation → §9 Operational Response
→ §10 Reverse Proxy Myth → §11 Watch List → §12 Caveats
```

This is broadly the right shape. Specific tightening:

### Reorder

1. **Move §6 (Time-to-Exploit Compression) up to between §1 and §2.** It's the *motivation* for needing a model — "median TTE dropped from 251d to 11d" is the line that justifies why a CVSS-30d-SLA framework is structurally insufficient. Currently it sits between the model and external validation, where it's orphaned. Putting it in the motivation section turns it into the punch line for §1 ("here's why the old SLAs don't work") and the lead-in for §2 ("so we need a different signal — here's where exploits actually land").

2. **§7 (Kill Chain / OS Layer) belongs adjacent to §9 (Operational Response), not between §6 and §8.** The kill-chain finding is *the rationale* for the monthly-container refresh tier in the operational model. As-is, the reader meets the OS finding, then external validation interrupts, then the operational model uses the OS finding without the recent context. Move §7 to be §8b (right before the operational response section), or make the operational response section explicitly call back to it.

3. **§5 (Why Most Criticals Don't Get Exploited) should come *after* §4 (validation), not before.** It's currently positioned as supporting evidence for the model, but it's actually a *consequence* of the model — once you have a discriminator, you can ask "what's the population on the other side?" Move to §5b after §4.

### Cut

4. **§2c (Libraries: The Denominator Makes the Difference) is now redundant with the OSV caveat in §2 and the FOSS sub-7 page.** It restates "NVD undercounts libraries; use OSV." The caveat does that job in §2's intro callout. The §2c subsection bloats §2 without adding evidence. Cut, link to OSV-exploitation page or FOSS sub-7 page from the §2 callout.

5. **The §1 three-bullet "active development / infrequent / stable-stale" list is duplicated in §9's Cat 1/2/3 table.** Pick one place to introduce the categories. Recommend keeping §1's narrative version (it sets up the Cat-2-mix problem at portfolio scale) and cutting the duplicated framing in §9 down to "as introduced in §1, three operational profiles..." with the table still present. Right now both sections do the full setup.

6. **§5's pattern list ("firmware/hardware, kernel local privesc, consumer IoT, memory corruption, OSS variance, non-Western ecosystems") is six bullets where two carry the load.** The kernel-LPE-as-chaining and the OSS-variance-jackson-databind paragraphs are the only ones that connect to the model. The other four are consistent with the data but don't change the operational answer. Cut firmware/IoT/non-Western to a single sentence; keep kernel-LPE and OSS-variance as full paragraphs because they drive the operational tiers.

### Add

7. **Add a "How to validate this against your own portfolio" subsection at the end of §9 or as §9b.** The current "Use this tomorrow" checklist is good but it's all *implementation* steps. There's no "how do I prove the filter is right for *me*" track. The 6-month tracking model is mentioned but not articulated as a recipe. Even five lines: "Pick your 50 most-deployed packages. Tag NP/non-NP. For 90 days, log every C/H disclosure against your manifest. Score: triggered / not-triggered. At 90d, cross-check against KEV adds during the period. Report misses publicly."

8. **The DI CWE freeze + public-miss counter deserves its own walkthrough subsection (probably §3c or §4g).** The freeze is the answer to the "you fit the filter to the data" critique; right now it's only on the dashboard and barely mentioned in the walkthrough. A 200-word section explaining the freeze policy, the rescue-path logic (hacker S+A is the only legitimate rescue from disclosure day forward), and pointing at the dashboard counter would tie the methodology section to forward-validation evidence.

9. **Add a short "what this analysis is NOT" section near §12 caveats.** The walkthrough is currently silent on what the model doesn't claim:
   - It doesn't predict *which* attacker will exploit something
   - It doesn't replace a CVSS-aware risk register for compliance reporting
   - It doesn't apply to commercial vendor patching (Cisco/MS Patch Tuesday — that's solved differently)
   - It doesn't claim equal performance on non-Java estates yet
   Three or four bullets, dropped in to set scope.

### Keep as-is

- The TL;DR card at the top
- The "How to read this site" navigation table
- §3's two-operationalizations framing (the structural insight is the right backbone)
- §4f real-world manifest with the strategy efficiency table — this is the strongest single piece of evidence on the page and it's positioned correctly
- §8a WAF defensibility — concentrated and tight, nothing to change
- §11 watch list — the prospective hit-rate framing is exactly what should be in the walkthrough

### Should periodicity.html stay separate?

**Yes, keep it separate.** Two reasons:
- The walkthrough is now ~1,225 lines and folding periodicity (~1,140 lines) in would push it past the boundary where a reader can actually finish it. The current "30 minutes for the walkthrough, click through to periodicity if you want the methodology depth" split is honest about the audience.
- The periodicity page is itself densely cross-referenced (Tomcat-PUT timeline, EPSS marginal-cost, monthly heatmaps) and the walkthrough already inlines the punchline tables (4b, 4f) and links to the detail. The architecture works.

What I'd change about the relationship: the walkthrough should be the canonical *what* + *why*, periodicity should be the canonical *how* + *receipts*. Right now both pages independently make the case; deduplicating is harder than it looks because each page has narrative momentum. But the explicit framing of "walkthrough = argument; periodicity = evidence" should be in the navigation copy and on the periodicity intro ("This page is the methodology and per-event detail behind the walkthrough's claims"). The periodicity page intro currently reads as if it's the primary analysis — both pages can't be primary.

---

## 3. Dashboard Updates

### What's working

- **The 10/11 union-catch and the freeze counter are the right two hero items.** They land the discrimination story and the forward-validation policy in the first screen.
- **The "Live tracker — April 1, 2026 forward" is exactly the right operational artifact.** It's the dashboard equivalent of the freeze counter — running ledger of how the model performed on this month's CVEs, with the "Other side of the argument" callout already built in. Keep this.
- **The Java-only manifest-scope yellow callout** is the kind of honesty that should be on the periodicity page too (see §1.3 above).
- **The "Three Response Lanes" card pattern** is the right summary of the walkthrough's §9 in dashboard form.

### What to add

1. **A "Strategy comparison at a glance" card** with the 4-row table from walkthrough §4f / periodicity §7 (NP+DI raw 5/11, +DQ 8/11, hacker 9/11, union 10/11). The dashboard has it as a wide table but it's buried under the periodicity-section heading. Promote to a small card near the hero KPI so the union/efficiency numbers are visible without scrolling.

2. **A "WAF defensibility" small card** showing the 4 / 7 / 1 / 1 split (FRIENDLY / MEDIUM / HOSTILE / +pre-2018). One line of context. This is the third-axis finding from periodicity §8a/walkthrough §8a and it's not on the dashboard at all currently.

3. **An EPSS marginal-cost summary card.** "EPSS ≥ 0.50 standalone: 21 patch events. Marginal on top of NP+DI+DQ: 1." That single comparison reframes EPSS faster than a chart can. Right now the dashboard has the EPSS chart but not the marginal-cost insight.

4. **A "Confirmed exploit watch-list track record" KPI band** is partly there (5/19 promoted, 14 active, 0 false positives). Recommend adding lead-time-to-KEV as a fourth tile (already shown as ~4d). The Spring AI 5-CVE addition is worth calling out as the first prospective test for the auto-monitoring loop — that's a one-line note.

### What's redundant or stale

5. **The "Cross-Framework: All C/H Dates vs NP+DI Dates" chart and the "OS Container Privesc Accumulation" chart sit side-by-side in the same row.** They tell different stories — workload reduction vs blast-radius management — and putting them on the same row implies they're parallel measurements of the same thing. Recommend separating: cross-framework chart goes in the "12-month workload" section near the live tracker; chaining chart goes in a "blast radius / kill chain" section near the response lanes.

6. **The Glasswing/Mythos card now points to a separate page**, which is correct, but the "Mythos intelligence assessment has been moved to a dedicated page" placeholder section eats vertical space without information. Replace with a 2-line summary: "Glasswing/Mythos: 283 vendor-attributed CVEs; 6 explicitly Claude-credited (CVE-2026-4747 FreeBSD NFS, CVE-2026-5194 wolfSSL, CVE-2026-5588 Bouncy Castle, CVE-2026-6746/-6757/-6758 Firefox 150)." Then the link.

7. **The "Finance Sector KEV Blind Spots" details pane is a reasonable supplementary card** but it's inside the same `<details>` accordion as Reverse Proxy Defense-in-Depth. Both are walkthrough content, not dashboard content. Recommend collapsing to a single "Walkthrough sidelights" details accordion with both inside, or deleting from the dashboard entirely (they're available via index.html links).

### Charts/tables that should move from periodicity → dashboard

8. **The monthly heatmaps (Spring/Node/Django/Netty) on the periodicity page are dashboard material**, not walkthrough material. They visualize the burst-pattern claim better than any other chart on the site. Worth a "Monthly burst patterns" card with all four heatmaps in a 2×2 grid.

9. **The strategy efficiency table from periodicity §7 is already on the dashboard** but the version on the dashboard cuts off the "Efficiency (overhead per exploit)" column in the snippet I read. Verify the column is there in production; if not, add it. This is the single line that converts "high catch rate" to "per-exploit overhead = 1.2× for hacker, 3.8× for NP+DI+DQ, 7.5× for patch-all" — that ratio is the operational sales pitch.

---

## 4. Cross-Page Architecture

### Front door (recommendation for the new reader)

Currently `index.html` is the canonical front door (sitemap + canonical URLs point at it). That's correct. But the "How to read this site" navigation table near the top is doing too many jobs. Recommend simplifying to three modes:

| Want | Read |
|------|------|
| The argument | This page (walkthrough) |
| The evidence | [Periodicity Analysis](periodicity.html) and [CVE Reference](cve-reference.html) |
| The live ledger | [Dashboard](dashboard.html) |

Everything else (Operational Model, Mythos, Evergreening, FOSS sub-7) becomes a "deeper reading" section below the table. The current 7-row table is already the right *content*, but it doesn't visually scaffold the reader's choice. The 3-row version sets up walkthrough → periodicity → dashboard as the canonical funnel, which is also the actual reading order.

### Page roles, formalized

- **`index.html`** — argument. Should make the case in 30 minutes of reading. Inlines the punchline numbers; links out for evidence depth.
- **`periodicity.html`** — evidence and methodology. Should be the page a skeptical reviewer reads. Per-CVE detail, EPSS comparison, OS NVD-noise correction, WAF-defensibility tagging.
- **`dashboard.html`** — live ledger. Daily-refreshed numbers, freeze counter, watch-list track record, monthly inbound. The argument-and-methodology pages are static-ish; this is the moving artifact.
- **`cve-reference.html`** — auditable per-event source. Treated as the supplementary evidence appendix. Most readers won't open it; the ones who do are the ones who matter.
- **`build-mechanics.html`** — operational play. The "what does this mean for how you actually run a portfolio" page. Cat 1/2/3 framing lives here canonically; walkthrough §9 is the digest.
- **`glasswing.html`** — speculative AI-disclosure tracking. Clearly labeled as speculative and separated.
- **`evergreen.html`** and **`foss-sub7.html`** — scratch / supplementary analyses. Should be one-click from index.html but not in the canonical reading path.
- **`osv-exploitation.html`** — scratch analysis. Same as above.

### Navigation top-bar

The current `<nav class="page-nav">` lists Overview / Periodicity / Operational Model / Evergreening / Mythos / Dashboard / CVE Reference. That's seven items, which is the upper bound for a top nav. Recommend reordering to reflect the canonical reading path: **Overview → Periodicity → Dashboard → CVE Reference → Operational Model → Mythos → Evergreening**. The current order intersperses methodology and supplementary pages; the proposed order goes argument → evidence → live → audit → operational deepening → speculative.

### Specific link-fixes I noticed

- `docs/index.html` line 859 references `glasswing.html#today` — verify the anchor exists on the Mythos page; it's the live daily-run scorecard pointer.
- The walkthrough's references to "the periodicity page" sometimes use `#strategy-efficiency`, `#tomcat-put-timeline`, `#chaining`, `#epss-comparison` — verify all four anchors exist in `periodicity.html`'s current state. (I confirmed `#tomcat-put-timeline` and `#epss-comparison` exist; the others I didn't grep specifically but the sidebar TOC suggests they do.)
- The walkthrough's `cve-reference.html#cohort-12m` and `#cohort-7yr-manifest` deep-links match anchors that exist in `cve-reference.html`. Good.

---

## 5. Daily Scan (2026-05-03)

**KEV.** Catalog version `2026.05.01`, total entries **1,587**. Seven new entries since last run:
- 2026-05-01 — `CVE-2026-31431` Linux Kernel — incorrect resource transfer between spheres. **Out of NP+DI scope** (kernel privesc, not network parser); chaining/blast-radius category, not initial access. Hacker tier C.
- 2026-04-30 — `CVE-2026-41940` cPanel & WHM / WP2 (WordPress Squared) — auth bypass on web admin interface. **NP+DI candidate** (web admin = NP, auth bypass via input manipulation = widened DI under CWE-287/289/306/863). Hacker A on default-config × edge × primitive-direct. Worth adding to the watch-list as a CONFIRMED hit if not already there.
- 2026-04-28 — `CVE-2024-1708` ConnectWise ScreenConnect — path traversal (already on watch list, retro-listing).
- 2026-04-28 — `CVE-2026-32202` Microsoft Windows Shell — protection mechanism failure (browser-delivered chain candidate, hacker A on client rubric).
- 2026-04-24 — `CVE-2025-29635` D-Link DIR-823X — command injection (CWE-78, NP+DI structurally; networking appliance, not in our manifest scope).
- 2026-04-24 — `CVE-2024-7399` Samsung MagicINFO 9 Server — path traversal (CWE-22, NP+DI structurally).
- 2026-04-24 — `CVE-2024-57728` and `CVE-2024-57726` SimpleHelp — path traversal + missing authorization (CWE-22 + CWE-862, both NP+DI under widened set).

**Glasswing/Mythos.** Total Mythos-attributed CVEs unchanged at **283** (Firefox 271, wolfSSL 9, F5 NGINX Plus 1, FreeBSD 1, OpenSSL 1). No new Claude-credited CVEs surfaced in the May web search. Six explicitly Claude-credited CVEs remain: `CVE-2026-4747`, `-5194`, `-5588`, `-6746`, `-6757`, `-6758`. Confirmed via flyingpenguin and TheNextWeb that only **3 of the Firefox 150 CVEs** carry the explicit "using Claude from Anthropic" credit string in MFSA 2026-30 — the other 268 are aggregated under the 271-found-in-one-eval-pass framing. Worth tightening the language on the Mythos page if it currently reads "271 Claude-credited" rather than "271 found in one Mythos eval pass, of which 3 carry explicit credit and 41 are CVE-tier" (per the existing CLAUDE.md guidance).

**Glasswing participants cross-check.** Of today's 7 new KEV entries:
- ConnectWise — not on participant list
- cPanel/WP2 — not on participant list
- Microsoft — **on participant list**, but Windows Shell CVE-2026-32202 has no Mythos attribution and pattern is consistent with traditional MSRC disclosure cadence (Patch Tuesday CVE)
- D-Link, Samsung, SimpleHelp — not on participant list
- Linux Foundation — **on participant list**; the kernel CVE has no Mythos attribution and is a typical kernel-LPE disclosure

No fresh Mythos signal in today's KEV adds. Nothing rises to "probable participant" qualification under the 2026-04-29 calibration (participant vendor + HTTP-adjacent + no attacker exploitation + no third-party credit + automated-scan bug pattern).

**April 2026 KEV entries: 31** (last run had 30; added one over the weekend — `CVE-2026-41940` cPanel on Apr 30). Watch list track record holds at **5/19 promoted, 0 false positives** if cPanel goes on the list as a same-day/next-day add.

---

## 6. TL;DR of recommendations

1. **Walkthrough**: small surgery, not major. Move §6 (TTE) into the motivation; pull §7 (kill chain) next to §9 (operational); cut §2c (library denominator) and the firmware/IoT/non-Western bullets in §5; add a "validate this against your own portfolio" recipe and a "what this is NOT" scope card; promote the freeze-counter framing into the methodology section.
2. **Periodicity page**: hard-cut the "zero misses on 12-month synthetic stacks" hero claim; soften the "leading indicator" paragraph; add manifest-provenance paragraph; replace Mythos-spike-attribution speculation with "interesting, watching"; fix the Node 1 vs Node 3 hacker-S+A inconsistency between §3 and §4.
3. **Dashboard**: promote the strategy-efficiency table to a hero card; add a WAF-defensibility small card; add an EPSS-marginal-cost summary; separate cross-framework chart from chaining chart; replace the Mythos placeholder with a 2-line summary; move the monthly heatmaps over from the periodicity page.
4. **Cross-page architecture**: simplify the "How to read this site" table to a 3-mode version (argument / evidence / live); reorder the top-nav to match the canonical reading path; formalize page roles in the nav copy.
5. **Daily scan**: add cPanel `CVE-2026-41940` to the watch list as a CONFIRMED hit if not already; track the SimpleHelp twin as in-scope but out-of-manifest.

The work that's been done since the brief was written has already moved the walkthrough most of the way to the right shape. The remaining gap is editorial discipline (deduplication, ordering, hard-cut some hero claims that don't survive the page's own caveats) rather than rebuilding.
