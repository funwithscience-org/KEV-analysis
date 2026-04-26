# Hacker as a safety-net for NP+DI's holes — Round 3 (N=175)

**Date:** 2026-04-25
**Question:** "How risky is what NP+DI misses, and which of the hacker's tiers would we have to adopt to safely close our own hole?"
**Inputs:** `analyst-reports/2026-04-25-hacker-ranking-v3.md` (hacker tiering of full 175-event Spring/Java manifest, blind to NP+DI labels), `data/seven-year-manifest-events.json` (NP+DI flag and exploitation outcomes per event)

## Summary up front

NP+DI catches 5 of 11 exploited events on the 7-year manifest (45% recall). The 6 it misses break into two patterns: (a) deserialization bugs the filter excludes by design (CWE-502 not in DI), (b) CWE-misclassified events tagged with generic CWEs (-269, -20, -44) that hide their real primitive shape. The hacker, blind to outcomes AND blind to NP+DI labels, **independently flagged all 6 misses at A or S tier**.

Adopting **NP+DI ∪ hacker-S+A** as the policy gets 100% recall on the exploited set at the cost of 26 extra patches per 7-year window (60 events flagged vs. NP+DI's 34).

If you want a tighter union: **NP+DI ∪ hacker-S** gets 64% recall at +2 patches. If you replace NP+DI entirely with hacker-S, you get the same 5/11 = 45% recall at 100% precision (5 of 5 events flagged are actually exploited).

## The 11 exploited events, tier and NP+DI status

| CVE | Package | CWEs | Hacker tier | NP+DI | Why NP+DI missed |
|---|---|---|---|---|---|
| CVE-2019-0232 | tomcat-embed-core | CWE-78 | **B** | ✓ | (caught) |
| CVE-2020-1938 | tomcat-embed-core | CWE-269 | A | ✗ | CWE-269 not in DI; real primitive is CWE-22 path traversal via AJP |
| CVE-2021-39144 | xstream | CWE-306, 502, 94 | **S** | ✓ | (caught) |
| CVE-2021-44228 | log4j-core | CWE-20, 400, 502, 917 | **S** | ✓ | (caught) |
| CVE-2021-45046 | log4j-core | CWE-502, 917 | **S** | ✓ | (caught) |
| CVE-2022-22965 | spring-beans, spring-webmvc | CWE-74, 94 | A | ✓ | (caught) |
| CVE-2022-42889 | commons-text | CWE-94 | A | ✗ | commons-text is role=OTHER (utility, not parser); NP rule excludes |
| CVE-2022-1471 | snakeyaml | CWE-20, 502 | **S** | ✗ | snakeyaml is role=OTHER (utility); CWE-502 not in DI |
| CVE-2023-46604 | activemq-client | CWE-502 | **S** | ✗ | CWE-502 not in DI; NP yes (broker is parser) |
| CVE-2025-24813 | tomcat-embed-core | CWE-44, 502 | A | ✗ | CWE-44 + CWE-502 not in DI; NP yes (Tomcat) |
| CVE-2026-34197 | activemq-broker | CWE-20 | A | ✗ | CWE-20 not in DI; NP yes (broker) |

The pattern: **every single NP+DI miss landed in hacker-S or hacker-A**. The 4 in tier-A and 2 in tier-S are exactly the events where the CWE label undersells the realistic primitive (CWE-269 hides AJP file-read, CWE-20 hides ActiveMQ Jolokia code injection, CWE-44 hides Tomcat partial-PUT chain) or where the package classification undersells the trust boundary (commons-text is utility-coded but its StringSubstitutor IS a network-edge parser; snakeyaml is utility-coded but its constructor IS a deserializer).

The hacker also down-tiered one NP+DI hit to B: CVE-2019-0232 (Tomcat CGI Windows-only). The hacker's reasoning ("CGI servlet default-disabled, Windows-only") is correct in expectation but the world built a Metasploit module anyway. Same pattern as round 1.

## Adoption-policy table

The operational question: which policy do you adopt?

| Policy | Flag | TP | FP | Recall | Precision | Δ vs NP+DI |
|---|---|---|---|---|---|---|
| NP+DI only (status quo) | 34 | 5 | 29 | 45.5% | 14.7% | — |
| Hacker S only (replace) | 5 | 5 | 0 | 45.5% | **100.0%** | −29 events |
| Hacker S+A only (replace) | 44 | 10 | 34 | 90.9% | 22.7% | +10 events |
| NP+DI ∪ hacker-S | 36 | 7 | 29 | 63.6% | 19.4% | +2 events |
| **NP+DI ∪ hacker-S+A** | **60** | **11** | **49** | **100.0%** | **18.3%** | **+26 events** |
| NP+DI ∪ hacker-S+A+B | 128 | 11 | 117 | 100.0% | 8.6% | +94 events |

Reading the table:

1. **NP+DI alone caps at 45% recall.** This is the operational ceiling on the current filter; the 6 missed events are the structural holes.
2. **Hacker S alone is a perfect classifier with low recall.** 5 events flagged, all 5 actually exploited. If you treat hacker-S as a parallel "drop everything" tier alongside whatever your normal triage is, you don't pull in noise. But you also don't close the recall gap.
3. **Hacker S+A as a STANDALONE classifier is the surprise result.** 44 events, 10 actually exploited, 91% recall. The one event hacker-S+A misses but NP+DI catches is CVE-2019-0232 (the Tomcat CGI Windows bug — same one round-1 missed). That single event aside, hacker-S+A on its own outperforms NP+DI by every measure: 91% recall vs. 45%, 23% precision vs. 15%, with only 10 more events flagged.
4. **NP+DI ∪ hacker-S+A is the safety-net answer.** 60 events flagged, 100% recall on the 11 exploited, at 18% precision. It's the right answer to the question as asked: *what would we have to adopt to safely close our hole*?
5. **Going further (∪ hacker-B) doubles flag count for zero recall gain.** The B-tier of the hacker is not adding signal beyond S+A; the one B-tier event that overlapped with exploitation was the CGI bug already caught by NP+DI.

## What S+A actually looks like as a backstop

The 26 extra events that NP+DI ∪ hacker-S+A pulls in over NP+DI alone are mostly:

- The Spring Security auth-bypass cluster the hacker correctly placed in A (some are NP+DI already, some not — the hacker re-anchored on auth-decision CWEs which is what we wanted)
- The 6 NP+DI misses themselves (Tomcat AJP, snakeyaml, ActiveMQ ×2, commons-text, Tomcat partial PUT)
- Spring Boot actuator misconfigurations (CVE-2025-22235)
- Spring Framework path traversal (CVE-2024-38819)
- Thymeleaf SSTI pair
- Logback socket-deserialization (rare but real)
- Pgjdbc driver-level SQLi (CVE-2024-1597)
- The ~12 XStream cluster events the hacker didn't individually promote but treats as A by default

These are mostly events a thoughtful security team would also flag for review, so the "+26 patches" cost is partly absorbed by the work that's already happening.

## What the hacker did that NP+DI couldn't

The hacker's per-event reasoning explicitly named the cross-cutting rule: **a deserialization or RCE-class CVE co-tagged with CWE-306 / CWE-862 / CWE-285 / CWE-287 is more dangerous than the same primitive without the auth-missing co-tag**. NP+DI doesn't track auth-missing CWEs as part of DI (they were added in the widened DI set as 287/289/306/345/693/863/1321 — but the rule the hacker articulated is *combining* an auth-missing CWE with a code-execution CWE, not either alone).

Concretely: CVE-2021-39144 is co-tagged CWE-306 (missing auth) + CWE-502 (deser) + CWE-94 (code injection). NP+DI catches it because of CWE-94 (in DI). The hacker S-tiers it because the **co-tag pattern** is the strongest predictor — CWE-306 is the gem signal that says "this isn't a sometimes-reachable deserialization, it's an always-reachable deserialization." Same pattern would tag CVE-2026-34197 (ActiveMQ Jolokia, CWE-20 alone — "improper input validation") if it were re-classified to its real CWE-94 code-injection primitive.

The hacker basically reverse-engineered the missing-CWE-tag-correction layer that the periodicity-doc has been calling the "AI scan tier" all along.

## What about the false positives?

NP+DI ∪ hacker-S+A flags 60 events; 11 are actually exploited; 49 are not. Are those 49 *bad* false positives, or are they mostly things a defender should be patching anyway?

Looking at the FPs more carefully:

- ~12 are Spring Security CVEs that the hacker correctly identified as auth-bypass primitives (CVE-2024-22257, CVE-2024-38821, CVE-2025-41232, etc.). These are real bugs you should patch — they're "false positives" only in the strict sense of "no one is known to have built a public exploit yet."
- ~12 are XStream cluster members the hacker treats as A by default. XStream-the-package is known-bad in older versions; if you have it on the classpath you should be patching every CVE in the cluster.
- ~5 are Tomcat / Spring path traversals and SSRFs (CVE-2024-38819, CVE-2024-22243, CVE-2025-55752 etc.) that have legitimate exploitation potential.
- ~5 are recent (2025-2026) bugs where right-censoring is the explanation — the world hasn't had time to weaponize them yet.
- The remaining ~15 are genuine over-reach (jackson-databind cluster events the hacker A-tiered for "default-typing-on" subset, Tomcat smuggling, etc.).

So the 49 "false positives" are largely things a competent security team would prioritize to patch regardless. The pure *operational waste* is closer to ~15 events over 7 years — about 2 events per year of unnecessary patch effort, in exchange for recall going from 45% to 100% on actual exploitation.

## Counter-argument worth holding

There are three honest pushbacks on this conclusion:

**1. The 175-event sample is structurally biased toward the bugs we know about.** It comes from `_manifest-osv-cache.json`, which is the OSV pull for the Spring Boot manifest we're tracking. Of 11 exploited events, 5 are Tomcat / log4j / Spring (the most-attacked Java surface in history). If we re-ran on a manifest of less-attacked packages — or one where attackers haven't been working as long — both NP+DI's 45% recall and the hacker's 91% recall could be lower. The relative shape probably holds; the absolute numbers might not.

**2. Hacker-S+A is doing what a sophisticated AI/human review pass would do anyway.** "Review every CVE on a network-edge package and tag the ones with auth-missing co-tags" is roughly what we've been calling the "AI scan tier" all along. The hacker round just empirically validated that an outcome-blind operator-model classifies the same way. That's confirmation of the methodology, not a separate triage policy. In production, this would mean adding a programmatic CWE-co-tag check (e.g., "CWE-502 ∧ CWE-306 → S", "CWE-269 on a network-edge package → re-review") rather than literally running an LLM hacker persona on every quarterly batch.

**3. The 100% recall is on a finite, fully-back-tested sample.** Going forward, novel exploitation patterns (e.g., new CWE shapes that didn't appear in the 7-year window, new package categories) could create gaps that neither NP+DI nor the hacker's discriminator catches. The "safe" claim is bounded by the empirical distribution we measured. The **right framing is "this closes the historical hole; the forward-looking risk is novel patterns."**

The first counter-argument is the strongest. The 175-event manifest is heavily Tomcat / log4j / Spring; if your estate looks substantially different (more npm, more Python-app-not-Django-utility, more obscure protocol parsers), the recall numbers would shift.

## Implications

1. **Adopt NP+DI ∪ hacker-S+A as the headline triage policy** for any environment matching the Spring/Java manifest profile. Cost is +26 events per 7-year window (≈4 extra patches per year), recall is 100% on historical exploitation.
2. **Operationalize the hacker's discriminator**: codify "deser-class CVE co-tagged with auth-missing CWE → S; CWE-269/-20/-44 on a network-edge package → re-review per AI-scan tier" as a programmatic check. This captures the value of the hacker exercise without requiring an LLM to rank every batch.
3. **Re-test on a non-Java manifest** to see if the 91% standalone recall of hacker-S+A holds outside the JVM ecosystem. The round-2 cross-ecosystem result hinted that npm and Python-utility events have lower base rates of public exploitation, which would affect both NP+DI and hacker recall the same direction.
4. **Update the periodicity doc** to drop the "every NP+DI catches everything" framing and replace with the empirical recall numbers (NP+DI alone: 45%; NP+DI ∪ hacker-tier: 100%) plus the AI-scan-tier rationale for the missed CWEs.

## Summary numbers

- **NP+DI status quo: 45.5% recall on actual exploitation.** Six events get through.
- **Hacker S+A independently flags every single NP+DI miss.** All 6 hidden in NP+DI rejection set are A-or-S tier.
- **NP+DI ∪ hacker-S+A: 100% recall, 18% precision, +26 events over baseline.** Defensible safety net.
- **The hacker is reverse-engineering the AI-scan-tier corrections** (CWE-269 → CWE-22 on AJP, CWE-20 → CWE-94 on Jolokia, package-role override on commons-text/snakeyaml). This is empirical evidence the periodicity-doc's AI-scan-tier framing is the right structural fix.
