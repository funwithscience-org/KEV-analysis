# Hacker ranking vs. actual exploitation outcomes — Round 2 (N=101)

**Date:** 2026-04-25
**Inputs:** `analyst-reports/2026-04-25-hacker-ranking-v2.md` (hacker-persona blind ranking on 101 events), `data/seven-year-npdi-events.json` (actual KEV/MSF/EDB outcomes)
**Question:** Does the round-1 result (S-tier 100% precision, A-tier 0% precision) replicate at 3.4× larger N spanning 5 ecosystems?

## Methodology

Same blinding rules as round 1: outcome fields (in_kev, in_metasploit, in_exploitdb, exploited) plus EPSS (which is trained on the same exploitation evidence and would be circular) stripped from the input. The hacker was given CVE id, publication date, package, ecosystem, CWE, and OSV summary text. The is_np / is_di filter labels were also withheld because every event in the input was already NP+DI by definition. Hacker was explicitly told to disregard breach-news memory and famous-bug recognition.

The dataset jumped from 30 events (mostly Java/JVM, doc-canonical) to 101 events (Java 36, Python 30, Ruby 17, JS 17, Go 1, OSV-derived seven-year set). The exploitation base rate stayed similar: 16/101 = 15.8% (vs round 1's 5/30 = 16.7%).

## Headline numbers

| Tier | R1 N | R1 hits | R1 prec | R2 N | R2 hits | R2 prec |
|---|---|---|---|---|---|---|
| S | 3  | 3 | **100.0%** | 3  | 3  | **100.0%** |
| A | 12 | 0 | 0.0%       | 25 | 9  | **36.0%** |
| B | 12 | 2 | 16.7%      | 44 | 3  | 6.8% |
| C | 2  | 0 | 0.0%       | 29 | 1  | 3.4% |
| D | 1  | 0 | 0.0%       | 0  | 0  | — |

Cumulative on round-2:

- **S only:** 3/3 = 100% precision, 18.8% recall
- **S + A:** 12/28 = **42.9% precision, 75.0% recall**
- **S + A + B:** 15/72 = 20.8% precision, 93.8% recall
- **S + A + B + C:** 16/101 = 15.8% precision, 100% recall

## What replicated, what didn't, what's new

### S-tier replicates perfectly

Same 3 picks (Log4j ×2, Spring4Shell), 100% precision both rounds. Round-2 chose the same three events from a 3.4× larger pool with no ambiguity. The "default-config × network-edge × primitive-direct" all-three-axes signature is a stable identifier for the highest-conviction subset at this dataset size.

### A-tier 0% does NOT replicate — it was small-N noise

This is the meaningful update from round 1. R1's A-tier of 12 events showed 0 exploited; R2's A-tier of 25 events shows 9 exploited at 36%. Eight of those 9 are in the Struts2 OGNL bag (CVE-2020-17530, CVE-2016-3081, CVE-2012-0391, CVE-2013-2251, CVE-2013-2115, CVE-2013-1966, CVE-2013-2134, CVE-2011-3923) — old Java framework RCEs that all have Metasploit/ExploitDB modules. The hacker correctly identified them as "build for a campaign" but only weighted them down from S because surviving install base in 2026 is enterprise-legacy. In retrospect that A-tier reasoning was right twice: (1) the bugs are real and weaponizable, (2) the install base is narrow but high-conviction operators DID build modules for them.

The implication: A-tier is real signal, not noise. R1's 0% was the kind of zero you can get from 12 specific events all happening to be near-misses (jackson-databind needing default-typing on, spring-messaging needing a STOMP broker, MINA needing the Object codec wired up, late XStream RCEs needing a target like NSX). Round 2's bigger A-tier population includes the Struts bag, which exploits cleanly because OGNL is mass-scannable.

### B-tier dropped from 17% to 7%

R1 B-tier of 12 events had 2 exploited (Tomcat CGI Windows-only, late XStream RCE attached to NSX). R2 B-tier of 44 events has 3 exploited. The proportional drop suggests the bigger B-tier population is more honestly "chain-into / niche" and the round-1 B-tier had a couple of unlucky placements.

### Recall@S+A is the operationally interesting number

If a defender treats S + A as "patch this week," they catch 12/16 = 75% of actual exploitation at 43% precision (4 false-positive patches per 3 true-positive). For an estate-wide triage policy, that's ~3× the base-rate precision (15.8%) with ¾ recall. That's a real classifier.

If they treat S + A + B as "patch this month," they catch 15/16 = 94% recall at 21% precision. Still ~1.3× base rate, and the one missed event would be the Django `_connector` SQLi (which the hacker explicitly named as the most likely member of the C-tier cluster, just rated below A overall).

### The 4 hacker misses

| CVE | Tier | Library | Why hacker tiered low | Actually exploited via |
|---|---|---|---|---|
| CVE-2019-0232  | B | tomcat-embed-core (CGI) | Windows-only, non-default CGI | MSF, EDB |
| CVE-2014-0130  | B | actionpack (Rails) | Path traversal = file read primitive, not RCE | KEV |
| CVE-2016-0752  | B | actionpack (Rails) | Same | KEV, MSF, EDB |
| CVE-2025-64459 | C | django (SQLi cluster) | "I'd build this one if I built any of the django bag" | EDB |

Three of four involve the hacker downgrading "weak primitive" (file read, conditional SQLi) when a weak primitive on a high-install-base framework actually accumulated public exploitation infrastructure. The fourth (Tomcat CGI) is the same Windows-only miss as round 1 — same operator-rational downgrade, same actual outcome of "someone built it anyway."

The pattern: **chain-into primitives (file read, SSRF, smuggling, partial SQLi) on huge-install-base frameworks accumulate exploitation evidence at a rate the hacker underweights**. The hacker is reasoning about what THEY would build; the world includes operators specifically targeting Rails / Django / Tomcat who'll build the chain-into module because the population is big enough to amortize the work.

## The discriminator, recalibrated

Round 1 conclusion: **default-config × network-edge × primitive-directness** identifies a HIGH-priority subset (S-tier). That conclusion holds.

Round 2 update: the **A-tier extension** — events that pass two of three axes — is also operationally useful. Specifically, "passes default-config + network-edge but is older / narrower install base" (Struts2 OGNL family) is *not* low-priority just because it's old. A specific high-value internal target running unpatched Struts2 in 2026 is exactly the kind of asset that gets owned.

Revised proposed split:

- **NP+DI / HIGH** ≡ NP package + DI CWE + (default-config × network-edge × direct primitive). S-tier. 100% precision both rounds. Same-day patch / WAF rule.
- **NP+DI / MEDIUM** ≡ NP package + DI CWE + (passes 2 of 3 axes; usually default-config + network-edge with a campaign-narrow install base, or strong primitive with a config-gate). A-tier. ~36% precision at R2 N, 75% cumulative recall. Patch this week.
- **NP+DI / LOW** ≡ NP package + DI CWE + (chain-into primitive OR fails 2-of-3 axes). B/C tiers. ~5% precision. Patch in regular cadence; elevate if local context (you ARE the Rails shop / you ARE the cert-auth Tomcat shop).

This is cleaner than round-1's binary HIGH/LOW split because it gives defenders a meaningful "this week vs. this month" boundary at A vs. B.

## Cross-ecosystem patterns

The hacker's per-ecosystem analysis turns out to be partially confirmed:

- **JVM (Maven)** dominates exploitation: 11/16 = 69% of exploited events are Java (Log4j ×2, Spring4Shell, Struts ×8). Hacker's "JVM is the operator-friendly ecosystem" prediction is borne out.
- **Python (Django)** lands one exploited event (the `_connector` SQLi the hacker correctly named as the most-likely member of the cluster). 1/16 = 6%. Hacker's "framework hardened, libraries fragile" prediction needed extension — Pillow ImageMath bugs that the hacker A-tiered did NOT show exploitation in this dataset, suggesting either right-censoring on the 2023+ entries or that the hacker over-rated Pillow's exploit attractiveness.
- **Ruby (Rails)** lands two exploited events (both ActionView path traversal). 2/16 = 13%. Hacker tiered both B; reality says they accumulated KEV/MSF/EDB modules. Mid-prediction.
- **Tomcat embed (server-edge Java)** lands one (the Windows-only CGI). Same miss as round 1.
- **npm (handlebars / next / axios)** lands ZERO exploited events. Hacker's "npm requires app-side conditions" prediction is borne out — none of the prototype-pollution / smuggling / SSRF events accumulated public exploit infrastructure.
- **Go** has only one event in dataset, not exploited.

The strongest cross-ecosystem takeaway: **JVM web frameworks are the empirical hot zone**. 69% of exploited NP+DI events at 7-year scale are Java. The discriminator's "default-config × network-edge × primitive-direct" all-three case is met most often by JVM data-binding shapes (Log4j, Spring data binding, Struts OGNL).

## Caveats

1. **Right-censoring**: 2024-2026 events have less time to accumulate public exploit modules. The Pillow ImageMath bugs and recent Spring path traversals may exploit-by-2027. R2's recall numbers are a lower bound on the true 7-year recall.
2. **Selection bias in the input**: `seven-year-npdi-events.json` is OSV-derived from popular package-manager packages. It over-samples libraries with rich CVE history (django 22, struts2 15, handlebars 10) and under-samples libraries with sparse CVE history (Go: 1). The 36% A-tier rate is partly a function of the Struts bag dominating A-tier; if we re-ran on a different package mix we'd see different numbers.
3. **CWE-shape vs. ecosystem confounding**: the hacker's per-ecosystem reads (JVM RCE-friendly, Python framework-hardened, Ruby framework-hardened) are partly tautological because the CWE distribution differs by ecosystem. JVM has more CWE-94/917; Python/Ruby SQLi clusters dominate the C-tier. We can't cleanly separate "JVM is more exploitable" from "JVM CVEs in this dataset are more often the high-conviction CWE shapes."
4. **Operator population isn't uniform**: the world's exploit-developer population is biased toward enterprise-target tooling (Cobalt Strike / Metasploit ship Java-stack modules first). KEV is biased toward US federal asset-relevant vulnerabilities. So "exploited per our definition" measures something narrower than "anyone in the world built a private exploit." A truly novel operator targeting npm/Python at scale would change the apparent base rates.

## Counter-argument worth holding

The Round 1 framing — "S-tier captures everything that matters" — was tighter and easier to act on. Round 2 gives a more accurate but messier picture: S-tier is necessary but not sufficient (only 19% recall), and the operational gain from A-tier extension is "patch 25 things to catch 12 vs. patch 3 things to catch 3." Some defenders will rationally choose round-1's narrow-S policy to minimize patch noise, accepting 80% miss rate on the recall side because each missed event is small-population.

The other side: 75% recall at 43% precision is a genuinely useful classifier. NP+DI alone gives 16/101 = 16% precision; HIGH+MEDIUM gives 12/28 = 43%. That's a 2.7× lift on the base rate while still acting on a tractable number of events per quarter. For a defender who can absorb 25 priority-patch decisions per quarter, this is the right setting.

## Updates to commitments

The doc-canonical periodicity-page framing should be updated:

1. **Drop the "every NP+DI event landed in NP+DI within window X" perfect-catch claim** — round 2's 100% recall only at S+A+B+C (i.e. all of NP+DI) confirms the small-N round-1 perfect-catch framing was over-promised. The doc's existing "12-month perfect catch" claim was already weakened by the 7-year extension; this round confirms it.
2. **Add the three-tier HIGH/MEDIUM/LOW rubric** with empirical precision/recall numbers, both round-1 and round-2 citing.
3. **Add a per-CWE-family note**: the Struts2 OGNL bag (CWE-94/917 in network-facing controllers) is the cleanest empirical predictor of exploitation across both rounds.

## Next steps

1. Re-run the same analysis with anonymized CVE IDs (Event-1...Event-101) to remove the residual name-recognition contamination from famous bugs.
2. Programmatically encode the three-axis discriminator (default-config / network-edge / primitive-direct as boolean per axis) and apply to the entire 7-year manifest event dataset (175 events) to see whether precision/recall holds at a more representative population.
3. Investigate the 4 hacker misses in detail — are there features visible in the OSV summary or CWE that would let the discriminator catch chain-into-primitives on huge-install-base frameworks?
4. Update `docs/periodicity.html` once the three-tier rubric is validated.
