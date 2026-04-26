# Analyst Review — Seventh Pass (2026-04-26)

This is the seventh-pass review of the periodicity analysis and the walkthrough/dashboard restructuring. It runs against HEAD as of 2026-04-26 morning, ~24 hours after pass 6. The brief in `analyst-reports/periodicity-review-brief.md` describes the pre-restructure state of the world; passes 4–6 walked the restructure in. Passes 6 and 7 are now status-of-the-restructure plus daily delta.

The headline change since pass 6 is not a new section or a copy edit — it is a new piece of data work that **directly contradicts the dashboard hero and the walkthrough TL;DR**. The 7-year per-framework backtest (commit `231dcae`, 2026-04-25 afternoon) and the per-CWE empirical exploitation backtest (commit `88dadc8`, same day) together rewrite the credibility envelope of the project. They are *good* additions — the per-CWE backtest in particular is exactly the empirical justification the DI-set widening has been missing — but the published HTML hasn't caught up.

I am going to lead with that gap, then walk the brief's four-part request, then drop the daily scan at the end.

---

## 0. Highest-priority finding: the new 7-year per-framework backtest contradicts the published "zero misses" claim

`data/seven-year-per-framework.json` (2026-04-25T14:43:28Z) extends the 12-month synthetic backtest out to a 7-year window and reports:

| Framework | Total C/H | NP+DI | Exploited | Caught | Missed | Catch rate |
|---|---|---|---|---|---|---|
| Spring | 145 | 25 | 6 | 2 | 4 | **33%** |
| Node.js | 70 | 14 | 0 | 0 | 0 | n/a |
| Django | 127 | 25 | 4 | 1 | 3 | **25%** |
| Netty | 10 | 3 | 0 | 0 | 0 | n/a |

Spring and Django combined: 10 exploited, 3 caught, 7 missed. **30% catch rate over 7 years.** That is not "zero misses." That is not the headline the dashboard and the walkthrough TL;DR are still presenting.

The misses are the same archetype the 7-year real-manifest backtest in periodicity.html §"Real-World Manifest" already disclosed:

- **CVE-2020-1938 (Tomcat Ghostcat)** — Tomcat AJP file disclosure → RCE. NP-true, DI-false (CWE-269 only). The CWE assignment doesn't reflect the bug class.
- **CVE-2025-24813 (Tomcat PUT RCE)** — NP-true, DI-false (CWE-44 + CWE-502). Not in DI by design after CWE-434 was removed in commit `a12f8ba`.
- **CVE-2026-34197 (ActiveMQ Jolokia)** — NP-true, DI-false (CWE-20 only).
- **CVE-2023-46604 (ActiveMQ OpenWire)** — NP-true, DI-false (CWE-502 — deserialization).
- **CVE-2022-1471 (snakeyaml)** — NP-false, DI-false. Mis-used yaml parser in network-facing apps.
- **CVE-2022-42889 (Apache Commons Text / Text4Shell)** — NP-false, DI-true (CWE-94). Library-utility being used to evaluate attacker-controlled input.

Five of seven misses cluster on two CWE families: **CWE-502 deserialization** and **CWE-20 input validation that gets used as a security boundary**. One is a CWE-269 mis-assignment (Ghostcat). One is a not-classified-as-NP utility library used in a network-facing role (Text4Shell).

The honest frame here is: **the filter is good at catching what it's defined to catch, and it has a structural blind spot for deserialization-driven RCE in NP packages and for evaluator-style utility libraries (StringSubstitutor, snakeyaml) used in network-facing roles.** Both failure modes are real, both are now empirically quantified, and both can be addressed — but they aren't yet.

The required response is two-part:

1. **Copy edit the published "zero misses" claims** so they're scoped to the 12-month synthetic stack window. The 7-year backtest is not zero-miss; saying it is reads as a falsified claim once the 7-year backtest data is in the repo (which it now is).
2. **Surface the deserialization blind spot explicitly** — not in caveats, in the body of §6 / §7 / §10. The pattern is consistent enough across Log4Shell (caught — it has CWE-917 too), ActiveMQ OpenWire, ActiveMQ Jolokia, Tomcat PUT, snakeyaml, and Text4Shell that "if your manifest contains a deserialization-capable component on a network-facing path, treat its CVEs at Tier 1 even when the CWE doesn't say injection" deserves its own line in the operational model.

This is the single highest-leverage edit available right now. It costs roughly 30 minutes of editing across three pages and it lands the strongest piece of new analysis. Not doing it leaves the repo in a state where the workbook (periodicity.html §"Real-World Manifest") admits 3 misses, the dataset (`data/seven-year-per-framework.json`) reports 7 misses, and the marquee (dashboard hero, walkthrough TL;DR, periodicity conclusion) all say "zero misses." A reviewer who looks at the repo for 20 minutes will land on that contradiction.

---

## 1. Assessment of the Periodicity Analysis (against current HEAD)

### 1.1 NP+DI methodology — now empirically validated, with a useful new pressure test

The most important methodology development since pass 6 is the per-CWE exploitation backtest in `data/di-cwe-backtest.json`. This computes, for every CWE in the DI set and a small control set (CWE-434, CWE-502, CWE-269, CWE-79), the empirical exploitation rate over C/H CVEs published 2022+, using the union of KEV ∪ Metasploit ∪ ExploitDB as the exploitation flag.

Reading the table:

- **Strong signal CWEs (≥4%)**: CWE-917 (16.7%), CWE-91 (15.4%), CWE-444 (8.8%), CWE-94 (6.5%), CWE-306 (5.2%), CWE-287 (4.9%), CWE-22 (4.7%), CWE-78 (4.5%), CWE-116 (4.4%). All defensible inclusions.
- **Borderline CWEs (1–4%)**: CWE-77 (3.8%), CWE-863 (3.1%), CWE-918 (2.3%), CWE-345 (2.2%), CWE-611 (1.85%), CWE-89 (1.5%), CWE-74 (1.3%). Most of these are well-attested injection patterns; the rates are softened by very large denominators (CWE-89 at n=4276 has 66 exploitations; the small percentage doesn't disqualify the inclusion).
- **No empirical signal (0%)**: CWE-95, CWE-1336, CWE-90, CWE-776, CWE-113, CWE-23, CWE-36, CWE-98, CWE-93, CWE-96, CWE-97, CWE-1236, CWE-289, CWE-693, CWE-1321 (CWE-1321 has 1 MSF entry, others 0).
- **Control comparisons**: CWE-434 = 4.14%, CWE-502 = 4.31%, CWE-269 = 2.28%, CWE-79 = 1.19%.

The headline empirical finding here is that **CWE-502 (deserialization) — which is *not* in DI — has a higher exploitation rate (4.31%) than 8 of the CWEs that *are* in DI**. This is exactly the result the 7-year per-framework backtest just confirmed in the wild: deserialization is a major exploited class that the filter isn't catching.

This is also the strongest possible counter to the goalpost-moving criticism from pass 5/6. The DI set is now testable against an objective metric (per-CWE empirical exploitation rate vs. CWE-434 baseline). New CWEs being added or removed can be defended or attacked on that basis. Removing CWE-434 in `a12f8ba` was the right call — it has lower exploitation than several DI members, and Tomcat-PUT-style misses were being miscoded as catches in the 12-month stack.

What's still soft:

- **The 0%-rate CWEs (CWE-95, -1336, -90, -776, -113, -23, -36, -98, -93, -96, -97, -1236, -289, -693, -1321) are in DI on patternist grounds, not on empirical grounds.** Half of them are essentially never assigned in NVD (denominators of 1–15). The defense is "these are rare-but-attested injection patterns and we want to flag the next CWE-95 event." That's fair. But the analysis should note explicitly that ~15 of the 21 DI CWEs carry no observed exploitation in the 4-year window, so the empirical weight of the filter rests on ~6 CWEs (mostly CWE-22, -78, -77, -94, -287, -306).
- **CWE-444 was added on 2026-04-22 to fix one Netty miss.** That's one event of motivation for an 8.8%-exploitation-rate CWE that probably should have been there from the start. The CWE-set changelog (still not on the walkthrough) should disclose that ordering: the change was retrospectively justified by the empirical rate, not the empirical rate motivating the change.
- **The auth-bypass widening (CWE-287/289/306/345/693/863/1321 added 2026-04-23) is half-supported by the empirical data and half not.** CWE-306 (5.2%) and CWE-287 (4.9%) clear the bar. CWE-863 (3.1%) and CWE-345 (2.2%) are borderline. CWE-289, CWE-693, CWE-1321 have effectively zero signal. The walkthrough should either drop the empirically-empty members or explicitly note "these were added on patternist grounds; they have not yet appeared in any exploited C/H CVE in the validation window."

The package-role-aware NP fix in `a12f8ba` is also significant. Previously, `commons-text` was being tagged `is_np=true` because it had a CWE-94 entry, even though commons-text the *package* is a utility library (role=OTHER). After the fix, commons-text correctly becomes NP-false in the manifest event dataset. This means the Text4Shell miss is now correctly classified as a miss, not silently miscategorized. Good.

### 1.2 Cross-framework validation — the 12-month version is now clearly distinguishable from the 7-year version

The brief asked whether the cross-framework validation is convincing. As of pass 6 the answer was "yes with a 14-14-14 caveat about analyst-authored manifests." As of today, the answer is more layered:

- **The 12-month synthetic backtest (Spring 5, Node 2, Django 6, Netty 1) is a clean coverage-of-ecosystems test and shows the filter aligning with exploitation evidence over a single year.** That result is real. It is also the result that has zero exploited CVEs in three of the four frameworks (Node and Django and Netty all have 0 KEV/MSF/EDB hits in the 12-month window per the dataset), so the "zero misses" claim is partly a function of low base rate over 12 months in those ecosystems. Spring's 12-month window has zero misses too, but that's against a base rate of 0 exploited C/H in window — not a strong test.
- **The 7-year per-framework backtest is a much stronger and harder test.** It has a non-zero exploited count in two of four frameworks (Spring 6, Django 4) and a non-zero miss count in both (Spring 4, Django 3). The catch rate is ~30%, not 100%.
- **The 7-year real-enterprise-manifest backtest** (the one that was already in periodicity.html §"Real-World Manifest" before pass 6) reports 27 NP+DI events of which 3 were missed — that's a 90% catch rate, much closer to the 12-month story. The difference is manifest scope: the real-manifest analysis includes a wider dependency set than the per-framework analysis.

So there are now three distinct results:
1. 12-month synthetic stacks: 100% catch rate, very low base rate
2. 7-year per-framework: ~30% catch rate, base rate of 7-10 exploited per framework
3. 7-year real-enterprise-manifest: ~90% catch rate (24/27)

**These are not contradictory — they're measuring different things — but the walkthrough only presents result (1) and result (3), without (2).** Result (2) is the bridge: it shows what happens when you take the synthetic-stack approach but extend the window. The catch rate falls. The reason matters: the misses are CWE-502/CWE-20 deserialization-and-evaluator events, which the filter doesn't claim to catch. The walkthrough should present (2) as a *deliberate* bound: "if you stick to the per-framework subset we used in the 12-month test but extend back 7 years, the filter catches roughly a third of exploited events. The remaining two-thirds are predominantly deserialization patterns the filter doesn't flag, which is why the operational guidance includes 'treat deserialization-capable components on network paths at Tier 1 regardless of CWE.'" That's an honest version of the story.

### 1.3 Kill chain framing — robust; the breakout-vs-privesc point still hasn't been promoted

No change since pass 6. The two-axis framing (app layer = IF, OS layer = HOW BAD) is correct and the data supports it. The recommendations from pass 6 §1.3 remain open:

- Surface "in-container privesc vs. container-breakout" distinction in walkthrough §8 (currently only in periodicity.html limitations footnote).
- Acknowledge systemd's 12-of-21 keyword inflation explicitly.
- Note that the OS-layer NP+DI=0 result is scoped to a base-image manifest that excludes orchestration/runtime/kernel — a Kubernetes pod sees the kubelet API and that surface isn't in the model.

These are 15–20 minute edits each.

### 1.4 External validation — EPSS section still strong; KEV/MSF/EDB framing is misleading at the new 7-year scope

The EPSS analysis remains the best single piece of work in the project. The Day 0 / Day 7 / Day 30 / Eventually table is the right way to present a real-time triage filter against a retrospective scoring system, and the conclusion holds.

The KEV/MSF/EDB sections of periodicity.html and walkthrough §9 still report "zero misses" against the 12-month window. That was always a thin claim because of KEV's enterprise/library coverage gaps. With the 7-year per-framework backtest now in the repo and showing 7 KEV-promoted exploited events not caught by the filter, the "zero misses" framing is no longer just thin — it's contradicted by the same project's own dataset. The fix is the copy edit in §0 above.

### 1.5 Devil's advocate — what could still undermine the conclusions

Carrying forward from pass 6 §1.5, with two additions and one revision:

1. **Survivorship bias in backtests** — unchanged.
2. **KEV is government-and-enterprise biased** — unchanged. Mitigated by the new MSF and EDB cross-checks.
3. **DI CWE set is versioned and was widened twice in two weeks** — partially addressed. The per-CWE empirical exploitation rate dataset (`di-cwe-backtest.json`) now provides an objective basis for inclusion/exclusion decisions, and CWE-434 was correctly removed in `a12f8ba` after sense-check pressure. **Remaining gap: the changelog isn't on the walkthrough.** Without a public versioning policy, the per-CWE table in the data file is a private precommitment, not a public one.
4. **April 2026 spike in the 12-month window** — unchanged. Forward validation against 2026-Q3 will be the real test.
5. **OS-layer NP+DI=0 result is partly a definitional artifact** — unchanged.
6. **"Burst not drip" is over-rotated on small samples** — slightly weakened by the new 7-year per-framework data. The 7-year per-framework view has more events and is consistent with bursty distribution (Log4Shell cluster, Spring4Shell cluster), so the framing is now better-supported. Still worth saying out loud in the walkthrough.
7. **NEW: the deserialization blind spot is the single biggest visible weakness in the filter.** CWE-502, CWE-94 in utility libraries, and CWE-20 mis-coded as input-validation when it's actually an evaluator boundary together account for 5 of 7 misses in the 7-year per-framework backtest. This isn't a hypothetical concern; the data shows it.
8. **NEW: the 7-year per-framework catch rate undercuts the headline in a way the 7-year real-manifest catch rate doesn't.** The real-manifest backtest reports 90% catch (24/27); the per-framework backtest reports 30% (3/10). The walkthrough presents the 90% number and not the 30% one. Either both should be presented (with the framing in §1.2 above) or the walkthrough should explain why the per-framework view is unrepresentative of how the filter would be deployed (answer: the per-framework view is a narrower manifest, deserialization-heavy, and it surfaces the blind spot more sharply because the manifest is smaller and the misses are more visible).

None of these kill the analysis. The deserialization point sharpens it materially.

---

## 2. Walkthrough Restructuring — what changed since pass 6, what's still open

The walkthrough §1–§14 structure landed in passes 4–6 is still the right structure (verified against current HEAD). No structural surgery needed. What's open:

### 2.1 Highest priority (today): scope the "zero misses" claims to the 12-month window

This was the highest-priority item in passes 5 and 6 and remains so, now with the additional weight of the 7-year per-framework backtest sitting in the repo as an obvious counterexample. Edits:

- **Walkthrough TL;DR (line 181)**: "with **zero misses** in 12 months" → "with **no exploited CVE missed in the 12-month synthetic backtest**. Extending the same per-framework manifests to a 7-year window catches ~30% of exploited events; the misses are predominantly deserialization-driven (CWE-502) and evaluator-utility-library (CWE-94 in commons-text). See §7g."
- **Walkthrough §9 in-plain-English (line 604)**: "Zero misses across 113 non-triggers." → "Zero misses across the 113 non-triggers in the 12-month window. The 7-year per-framework extension shows 7 KEV-promoted exploited events not caught (all deserialization or input-validation-as-evaluator patterns); see §7h."
- **Walkthrough §10 (line 690)**: "should produce zero misses" → "should approach zero misses on injection-class exploits within a 12-month rolling window; expect a residual deserialization miss rate that requires the Tier 1 deserialization-on-NP-path rule (§10b) to close."
- **Walkthrough §14 (line 924)**: '"zero misses"' → '"zero misses on the 12-month synthetic stack"'
- **Periodicity §Conclusion (line 545)**: "Across 113 non-trigger CVEs, four ecosystems, and 12 months: **zero misses.**" → "Across 113 non-trigger CVEs, four ecosystems, and 12 months: **zero misses.** Extending the per-framework manifests to a 7-year window finds 7 misses, all deserialization or evaluator-library patterns the filter explicitly doesn't claim to catch — see *Real-World Manifest* and *Limitations* below."
- **Periodicity §Conclusion (line 689)**: same framing.
- **Dashboard hero (line 165)**: "with zero misses — no filtered-out CVE has appeared in CISA KEV." → "with no app-layer non-trigger reaching CISA KEV in the 12-month window. The 7-year per-framework extension finds 7 deserialization/evaluator-class misses; see periodicity.html §Real-World Manifest."

Total: ~10 minutes of editing, clears the largest single credibility gap.

### 2.2 New: add a §7h — "What the Filter Doesn't Catch (the 7-Year Per-Framework View)"

Currently the walkthrough has §7g for the 7-year real-enterprise-manifest backtest (90% catch) and stops there. The new 7-year per-framework dataset deserves its own subsection. Structure:

> **§7h. Stress Test: Same Manifests, 7-Year Window**
>
> Holding the per-framework manifests constant and extending the validation window from 12 months to 7 years gives a much more discriminating test. The filter's catch rate falls from 100% (12 months, low base rate) to ~30% (7 years, 10 exploited events, 3 caught).
>
> | Framework | Exploited | Caught by NP+DI | Missed | Why |
> |---|---|---|---|---|
> | Spring | 6 | 2 | 4 | Ghostcat (CWE-269 only), Tomcat PUT (CWE-44/502), ActiveMQ Jolokia (CWE-20), ActiveMQ OpenWire (CWE-502) |
> | Django | 4 | 1 | 3 | snakeyaml (utility library), Text4Shell (utility library), commons-text (utility library) |
>
> The pattern in the misses is consistent: **deserialization-driven RCE (CWE-502)** and **evaluator-utility libraries used in network-facing roles (CWE-94 in commons-text, CWE-20 in snakeyaml)**. Both failure modes are addressed by the §10b Tier 1 deserialization-on-NP-path rule.
>
> This is the honest hard test of the filter. It catches the injection-pattern bugs it's defined to catch. It does not catch deserialization-driven RCE without explicit help, and it does not catch utility-library mis-use without an NP-classifier override. The operational model is constructed to handle both.

This is ~20 minutes of writing once the §10b rule (next item) is in place.

### 2.3 New: add a §10b — "The Deserialization Rule"

Currently the three-tier model is Tier 1 (NP+DI emergency) / Tier 2 (monthly container) / Tier 3 (ride the cycle). The 7-year per-framework data argues for an explicit deserialization carve-out:

> **§10b. The Deserialization Rule**
>
> NP+DI catches injection patterns. It does not catch deserialization-driven RCE — Log4Shell would have been caught (CWE-917 was assigned), but ActiveMQ OpenWire (CWE-502 only), Tomcat PUT (CWE-44 + CWE-502), and Apache Commons Text / snakeyaml in evaluator contexts would not.
>
> Operational rule: **a manifest entry that exposes a deserialization-capable component (Jackson, snakeyaml, commons-text, ObjectInputStream consumers, ActiveMQ broker) on a network-facing path is Tier 1 for any C/H CVE in that component, regardless of CWE.** This adds approximately 1–2 events per year per stack to the Tier 1 list. It is the single biggest empirically-justified addition we can make to the operational model right now.
>
> See `data/seven-year-per-framework.json` for the empirical basis: 5 of 7 misses across 7 years of Spring + Django are deserialization or evaluator-library patterns.

### 2.4 §6d — CWE Set Versioning & Changelog (still missing, now with empirical justification)

Pass 5 and pass 6 asked for this. The new `di-cwe-backtest.json` makes the case stronger because each CWE inclusion can now be defended on an empirical exploitation rate. Recommended structure:

> **§6d. CWE Set Versioning**
>
> The DI CWE set is versioned. Inclusions are defended against an empirical exploitation rate (KEV ∪ Metasploit ∪ ExploitDB across C/H CVEs published 2022+). Baseline: CWE-434 file-upload at 4.14% serves as the inclusion threshold; CWEs below that rate are included only on patternist grounds and flagged.
>
> | Version | Date | Change | Empirical justification |
> |---|---|---|---|
> | 1.0 | 2026-04-21 | Initial 13 CWEs | Patternist construction |
> | 1.1 | 2026-04-22 | + CWE-444 (request smuggling) | 8.82% exploitation rate, motivated by Netty backtest miss |
> | 1.2 | 2026-04-23 | + CWE-287, 289, 306, 345, 693, 863, 1321 (auth bypass) | CWE-306 5.2%, CWE-287 4.9% (above baseline); CWE-345 2.2%, CWE-863 3.1% (below baseline, included on patternist grounds); CWE-289, 693 (no observed events, included on patternist grounds — flagged) |
> | 1.3 | 2026-04-25 | − CWE-434 (file upload) | 4.14% baseline; Tomcat-PUT-style events were being miscoded as catches; sense-check identified the inconsistency |
>
> Future widenings will be appended. Set membership is not closed; new injection patterns may justify additions. Consensus criterion: addition must be defended either by patternist construction (with that flagged) or by empirical exploitation rate against the CWE-434 baseline. The justification must be made before the validation backtest is rerun, not after a new event is observed. Per-CWE empirical rates: `data/di-cwe-backtest.json`.

That last sentence is the goalpost-moving prophylactic. ~20 minutes.

### 2.5 §7 reorder — still pending

Pass 6 §2.3 recommended leading §7 with the 7-year real-manifest backtest. Still the right call. The new §7h proposed above (per-framework 7-year stress test) probably comes between the current §7g and a hypothetical §7-headline. Order:

- **7a. The Hardest Test: 7 Years of an Enterprise Java Portfolio** (move from current 7g)
- 7b–7g. Cross-ecosystem coverage (current 7a–7f)
- **7h. Stress Test: Same Manifests, 7-Year Window** (new — surfaces the deserialization blind spot)

### 2.6 Mythos breach disclosure — still pending

Pass 6 §5.3 recommended adding one sentence to §12. Still right. As of today, the breach is now ~5 days old, has been covered in Bloomberg, Fortune, Euronews, hackread, cybersecuritynews, plus follow-up commentary from Foreign Policy and AISLE. The "Mythos preview is the buffer" framing in §12 is now empirically weakened by the breach; one sentence captures it:

> "Anthropic confirmed unauthorized access to Mythos Preview on 2026-04-21 via a third-party vendor environment. The preview-era buffer that lets participant vendors fix findings before public disclosure is no longer hermetic; participant vendors should treat their pre-public findings as at higher leak risk than originally assumed."

### 2.7 Lower-priority items still open

Carrying from pass 6:
- §8 breakout-vs-in-container-privesc surfacing (~15 min)
- §10 Tier 2 justification ("monthly because bi-weekly only saves one CVE") (~10 min)
- §11 Reverse Proxy Myth — still interrupting the §10 → §12 narrative arc; move it earlier or fold into §14
- §14 "Limits of This Backtest" subsection consolidating dispersed honest-disclosures (~30 min)
- Pre-§1 hero block with 6-second pitch + cross-page nav cards (~45 min)

### 2.8 Should periodicity.html be folded in?

Still no. The pass-6 reasoning holds: walkthrough = narrative, periodicity = workbook, two different audiences. What *should* happen is the canonical-NP+DI-definition cleanup pass-6 §4.3 recommended: walkthrough §6 is canonical; periodicity.html and cve-reference.html link to it rather than re-defining.

---

## 3. Dashboard Updates

Current dashboard (post-restructure) is structurally right. Specific updates:

### 3.1 Hero copy (line 165) — fix the zero-miss overclaim today

Same edit as §2.1. The dashboard hero is the highest-traffic surface in the project and currently carries the most-falsifiable claim.

### 3.2 Add a 7-year per-framework chart

Pass 6 §3.3 asked for the 7-year real-manifest backtest as a chart. The new 7-year per-framework dataset is even better material for the dashboard because the per-framework comparison lines up cleanly with the existing 12-month per-framework chart. Two stacked-bar charts side by side — "12-month: trigger frequency reduction" and "7-year: exploit catch rate by manifest" — make the strength-and-limitation of the filter visible in a single eyeful.

### 3.3 Add a deserialization-blind-spot KPI tile

A small card: "**Catch rate on deserialization-driven RCE: 1 of 5 in 7-year per-framework backtest.** The §10b deserialization rule covers this gap." This is uncomfortable but it's the honest single number to put against the headline catch-rate claim. It also positions the §10b rule as a deliberate response, not an afterthought.

### 3.4 CWE-set version badge

Pass 6 §3.2. Still right. Now with empirical rates available, the tooltip should include the per-CWE table or link to it.

### 3.5 Watch-list KEV-promotion tile

Pass 6 §3.4 said this should be a hero KPI at 3-for-3, then corrected to 2-for-2. Today's status (per `kev-tracking.json`): no new watch-list promotions in the past 24h. The 2/2 record from the past 4 days is unchanged. The miss (Samsung MagicINFO not on the list) and the partial miss (SimpleHelp not on the list) cut the other way: the watch list is too narrowly scoped to mainstream tools and is missing mid-tier RMM and digital-signage gear. The tile should land as **"Watch list → KEV: 2/2 in 4 days; 2 KEV adds the list missed (SimpleHelp, MagicINFO)."** Honest framing on both sides.

### 3.6 What's stale or now redundant

The dashboard's existing "Exploitation Rate (KEV/NVD)" and "Critical/High Vulns per Package: Parser vs Non-Parser" charts are still load-bearing for the §3 observational case in the walkthrough. Keep them. The "KEV by CWE Family" chart could carry an overlay marking which CWE families are in the DI set — that's a useful visual cross-check between the observational data and the filter construction.

---

## 4. Cross-Page Architecture

Pass 6 §4 laid out the five-page architecture (walkthrough, dashboard, periodicity, cve-reference, glasswing) and the front-door problem. That all still applies. The two structural notes for today:

### 4.1 Stop the dashboard hero from carrying the most-falsifiable claim

The hero copy is the surface most likely to be screenshotted, quoted, or excerpted. It should carry the most-defensible claim, not the most-aggressive. "Reduces rebuild-trigger dates by 64–86% across three ecosystems" is the defensible claim (cross-framework reduction is the real number and survives the 7-year stress test). "Zero misses" is the aggressive claim (it requires a 12-month synthetic stack scope qualifier to be true). Lead with the defensible.

### 4.2 The data files should now be cited

`data/di-cwe-backtest.json`, `data/seven-year-per-framework.json`, `data/seven-year-manifest-events.json` are all reproducible artifacts now sitting in the repo. They should be cited from the walkthrough's methodology section and from periodicity.html's caveats. The current pages mention "see the cve-reference page"; they should also mention the data files for the per-CWE and per-manifest justifications. This is a low-effort credibility win — even one sentence of the form "raw per-CWE empirical exploitation rates: `data/di-cwe-backtest.json`" raises the project's audit posture meaningfully.

### 4.3 New pages noted

`docs/index-v2.html` and `docs/dashboard-v2.html` (~340–370KB each) still exist alongside `docs/index.html` and `docs/dashboard.html`. Commit `4173854` says "Promote v2 pages to main, retheme periodicity to light" but the v2 files weren't deleted. They're 80–90% the size of the published versions and are presumably the now-stale pre-promotion copies. They should be deleted to remove drift risk — if anyone ever links to `index-v2.html` or `dashboard-v2.html`, they'll be reading the pre-promotion content. Lower priority than the §0 copy edit but worth a `git rm`.

`docs/build-mechanics.html` (43KB, added 2026-04-25) is new. It's not in any of the inter-page nav bars I checked. Either nav it or note it in the README.

---

## 5. Daily Scan — 2026-04-26

### 5.1 KEV adds (24h)

CISA catalog version 2026.04.24 (count 1583) is the current published version. No new entries on 2026-04-25 or 2026-04-26 — the refresh agent's `kev-tracking.json` is current. The four 2026-04-24 entries (SimpleHelp pair, Samsung MagicINFO, D-Link DIR-823X) were already disclosed in pass 6 §5.1. CISA's BOD-22-01 deadline for the SimpleHelp + MagicINFO entries is 2026-05-08 per the techaiapp.com coverage.

**Watch-list cross-check**: no watch-listed CVEs were promoted in the past 24h. The 2/2-in-4-days record (CVE-2026-39987 Marimo, CVE-2026-33825 Defender) is unchanged.

**NP+DI candidate review** (per `kev-tracking.json` carry-over):
- CVE-2026-0234 (Palo Alto Cortex XSOAR, CWE-347, Glasswing participant) — refresh agent has flagged this for analyst review for the third consecutive run. Recommendation: add to probable-participant table. Strong fit (Glasswing vendor, HTTP-adjacent integration via Microsoft Teams marketplace webhook, CVSS 9.2, no third-party researcher credit, CWE-347 within widened-DI). Carry-forward not actioned today since the brief asks for analysis recommendations, not edits.

### 5.2 NVD volume

April 2026 MTD: 5,083 (day 26 of 30). Extrapolated 5,865. Day-over-day rate (46/day) is well below the running April average (~196/day) and consistent with a Sunday lull. April will land in the 5,800–6,200 range, in line with the Q1 2026 churn band (4,808–6,304). **No positive evidence of a Glasswing-driven volume shock.** The Mythos-volume-explosion thesis remains in the null. Counter-argument: NVD publication latency is 4–8 weeks, so Mythos disclosures from April may not appear in NVD until mid-May at earliest. Hold the position.

### 5.3 Mythos / Glasswing news

- **Foreign Policy (2026-04-20) and Council on Foreign Relations** are now both running long-form analysis on Mythos Preview as a strategic-policy story. The implication for the project: the §12 framing of Mythos as "the volume question is about to get worse" is now consistent with mainstream-policy discourse rather than ahead of it. No copy change needed; it just means the audience is now familiar with the context.
- **Anthropic Mythos Preview breach (2026-04-21–22)**: still the dominant Mythos-adjacent news cycle. Bloomberg, Fortune, Euronews, hackread, cybersecuritynews all in the past 5 days. No CVEs attributed to leaked-access actors yet, but the asymmetry the Mythos breach creates (leaked-access actors can scan for bugs while defenders cannot) is the operational concern. Worth the one-sentence walkthrough §12 addition recommended in §2.6.
- **AISLE blog post (2026-04-22)**: 5 of 7 OpenSSL April 2026 CVEs were AI-uncovered. Independent AI vulnerability finder (not Mythos), but the "AI scan tier" frame in periodicity.html applies. No project change needed; this is consistent with the existing §10 model.
- **No new Claude-credited CVEs in the past 24h.** Total Glasswing-attributable CVE count: 283 (271 Firefox, 9 wolfSSL, 1 each F5 NGINX Plus / FreeBSD / OpenSSL). The Firefox 150 / MFSA 2026-30 batch continues to dominate.

### 5.4 Glasswing-participant cross-check on today's KEV adds

None of the 4 entries added 2026-04-24 are from Glasswing participants. SimpleHelp, Samsung, D-Link are all non-participants. Confirmed not a probable-participant signal.

### 5.5 Net daily finding

Quiet day. The two material developments are backward-looking (the new 7-year per-framework backtest from yesterday and the per-CWE empirical exploitation backtest from yesterday afternoon — both are pass-7 §0 / §1 material above, not daily-scan material). The KEV catalog is unchanged from yesterday. NVD volume is consistent with the established April trajectory. Watch list is unchanged. No participant-attributable CVE adds.

---

## 6. Punch List — Carry-Forward + New (post-pass-7)

Sorted by leverage:

**Highest leverage (today, ~30 minutes total):**

1. ☐ Scope all "zero misses" claims to the 12-month synthetic stack window across dashboard hero, walkthrough TL;DR, walkthrough §9 / §10 / §14, periodicity Conclusion (~15 min)
2. ☐ Surface the deserialization blind spot — add §10b "The Deserialization Rule" to walkthrough; reference `seven-year-per-framework.json` in §7 (~15 min)

**High leverage (this week, ~2 hours total):**

3. ☐ Add walkthrough §7h "Stress Test: Same Manifests, 7-Year Window" with the per-framework 30%-catch-rate table (~20 min)
4. ☐ Add walkthrough §6d "CWE Set Versioning & Changelog" with empirical-rate justification table (~20 min)
5. ☐ Reorder §7 to lead with the 7-year real-manifest backtest, then 7h, then cross-ecosystem coverage (~30 min)
6. ☐ Add Mythos breach disclosure to walkthrough §12 (one sentence, ~5 min)
7. ☐ Add 7-year per-framework chart + deserialization-blind-spot KPI tile to dashboard (~45 min)
8. ☐ Add CWE-set version badge to dashboard near the cross-framework chart (~15 min)

**Medium leverage (this week, varies):**

9. ☐ `git rm docs/index-v2.html docs/dashboard-v2.html` if confirmed stale (~5 min)
10. ☐ Add SimpleHelp to server-side watch list with rationale "RMM web-admin parsing surface; KEV 2026-04-24 cluster" (~15 min)
11. ☐ Surface in-container-privesc vs. container-breakout distinction in walkthrough §8 (~15 min)
12. ☐ Surface systemd's 12-of-21 LOCAL-CWE keyword inflation in walkthrough §8 (~10 min)
13. ☐ Add CVE-2026-0234 (Palo Alto Cortex XSOAR) to probable-participant table — third carry-forward (~15 min)
14. ☐ Build-mechanics page navigation surface (~10 min)
15. ☐ Cite data files in methodology section and periodicity caveats (~15 min)

**Lower leverage (when convenient):**

16. ☐ Move §11 Reverse Proxy Myth out of the §10 → §12 narrative arc
17. ☐ Add §14 "Limits of This Backtest" consolidating dispersed honest-disclosures
18. ☐ Pre-§1 hero block on walkthrough with 6-second pitch + cross-page nav cards
19. ☐ Canonicalize NP+DI definition to walkthrough §6; trim periodicity.html and cve-reference.html to summary-plus-link

**Open from prior passes that are not directly addressable here:**

20. ☐ `tests/test_kev_classifier.py` with ~20 canonical examples (testing infra)
21. ☐ Triage the `other` bucket in `data/kev-layer-classifications.json`

---

## 7. Bottom line

The new 7-year per-framework backtest and per-CWE empirical exploitation backtest are the strongest pieces of evidence the project has produced — they're the empirical justification for the DI CWE set, and they're the honest hard test of the filter against a longer window. They also expose two findings the published HTML doesn't yet reflect: the filter has a structural deserialization blind spot, and the "zero misses" claim is true only at the 12-month synthetic stack scope. Both findings can be turned into project-strengthening additions (a §10b deserialization rule and a §6d CWE-set changelog) with roughly 30 minutes of editing.

The largest remaining risk to the project's external posture is not the analysis. It's the gap between what the data files now show and what the dashboard hero, walkthrough TL;DR, and periodicity Conclusion are still claiming. A reviewer who reads the data files and then reads the marquee will land on the contradiction. The fix is half an hour of copy editing and one new short subsection.

The architecture (five pages, periodicity = workbook, walkthrough = story, cve-reference = data, glasswing = intelligence assessment, dashboard = live state) is the right architecture and shouldn't be touched. The v2 leftover files should be deleted. The CVE-2026-0234 carry-forward is now on its third pass without action and should be either resolved (add to probable-participant table) or closed (decision to skip with rationale).

— pass 7 / 2026-04-26
