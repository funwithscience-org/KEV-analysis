# Analyst Review Brief: Periodicity Analysis & Walkthrough Rewrite

## What happened since your last run

A major new analysis has been published at `docs/periodicity.html` and `docs/cve-reference.html`. This work fundamentally extends the project's thesis from "network parsers get exploited more" (observational, backward-looking) to **"here's a testable filter that tells you when to rebuild, and here's 12 months of evidence that it works"** (prescriptive, forward-looking). The walkthrough (`docs/index.html`) and dashboard (`docs/dashboard.html`) have NOT been updated to reflect this — they still read as the original observational analysis.

## The new analysis (periodicity.html)

### Core concept: NP+DI filter
- **Network Parser (NP):** component parses network protocol data (HTTP, TLS, DNS, XML from network, template rendering, ORM SQL from user input)
- **Direct Injection (DI):** CWE indicates attacker can inject commands/queries/paths/code through the parsing surface (CWE-78, -77, -22, -23, -36, -94, -95, -89, -918, -917, -1336, -116, -74, -75, -113, -93, -611, -91, -90, -79)
- **Trigger rule:** emergency rebuild if and only if a C/H CVE is both NP AND DI. Everything else rides the normal 30-day release cycle.

### Cross-framework validation (3 stacks, 12 months each)
- **Spring Boot** (48 deps, 16 NP): 14 all-C/H dates → 2 NP+DI dates (85% reduction). Triggers: Tomcat path traversal, Thymeleaf SSTI.
- **Node.js/Express** (45 deps, 21 NP): 14 all-C/H dates → 2 NP+DI dates (86% reduction). Triggers: Koa host injection, Handlebars code injection.
- **Django/Python** (40 deps, 16 NP): 14 all-C/H dates → 4 NP+DI dates (71% reduction). Triggers: all Django ORM SQL injection.
- Pattern: silence punctuated by bursts, not a slower steady drip. Spring had 5.5 months silence then two hits in a week.

### OS container layer (Amazon Linux 2023, ~25 components)
- 69 C/H CVEs in 12 months, **NP+DI = 0**. OS layer never generates emergency rebuild triggers.
- 21 LOCAL privesc CVEs accumulated over the year — these are chaining paths after app-layer breach.
- At Spring's Oct 27 trigger (189d stale container): 11 local privesc CVEs available.
- At Spring's Apr 9 trigger (353d stale): 21 local privesc CVEs.
- Monthly container refresh drops worst-case privesc from 21 to 5 (76% reduction).

### Three-tier patching model (derived from data)
- **Tier 1 — Emergency:** NP+DI in app layer → rebuild everything (2-4x/year)
- **Tier 2 — Regular cadence:** monthly container refresh for blast radius control
- **Tier 3 — Ride the cycle:** everything else gets swept up in 30-day releases

### External validation (5 sources, 129 CVEs)
- **EPSS:** Triggers score 3.3x higher mean exploitation probability than non-triggers (app layer). Django SQLi at 89th percentile globally.
- **CISA KEV:** 1 hit — zlib (non-trigger, OS layer, exploited via MongoDB not our apps). Zero app-layer misses.
- **ExploitDB:** 2 hits — Django SQLi (trigger), sqlite heap overflow (non-trigger, local access).
- **Nuclei:** 1 scanner template — Django SQLi (trigger).
- **Metasploit:** 1 module — zlib/MongoDB (non-trigger).
- **Key insight: zero misses across 113 non-trigger CVEs.** The filter hasn't been wrong yet. It may be a leading indicator — identifying CVEs that will accumulate exploitation evidence before the scanners get there.

### Additional checks performed
- **NP + Use-After-Free:** adds exactly 1 event across all manifests (nghttp2 DoS). Not worth expanding the filter.
- **Below-HIGH severity NP+DI:** only 5 CVEs, mostly lower-severity variants of bugs already caught at HIGH. Signal-to-noise degrades as you go lower.

### CVE reference page (cve-reference.html)
- All 129 CVEs with NP classification, DI classification, trigger status, CWEs, EPSS scores, reasoning. Sortable, filterable, searchable. Exists for independent validation.

## What needs to change in the walkthrough (index.html)

The walkthrough was written before this analysis existed. Its current structure:
1. Hypothesis (HTTP parsing = exploitation predictor)
2. Methodology
3. Stack layer exploitation rates
4. Network parsers as exploitation predictor
5. Why most criticals don't get exploited
6. Time-to-exploit compression
7. Finance sector blind spots
8. CWE families & ransomware
9. Patch SLA framework
10. Mythos detector
11. Exploit watch list
12. Caveats

### The gap
The walkthrough makes the *observational* case (network parsers get exploited more) but never makes the *prescriptive* case (here's what you should do about it, here's how to test it, here's 12 months of evidence). The periodicity analysis is the payoff — it turns the observation into an actionable filter with measured false-positive and false-negative rates.

**Section 9 (Patch SLA Framework)** is the most obvious gap — it currently proposes SLAs based on CVSS severity tiers, which is exactly what the periodicity analysis shows doesn't work. The new model (NP+DI emergency / monthly container / ride-the-cycle) should replace or heavily supplement this.

The **three-tier patching model**, the **cross-framework validation**, the **OS chaining analysis**, and the **external validation** are all major new findings that the walkthrough doesn't mention at all.

The **dashboard** needs lighter updates — mainly adding the periodicity findings as a new section/chart and linking to the periodicity page.

## What needs to change in the dashboard (dashboard.html)

The dashboard is data-focused and auto-refreshed daily. Changes needed:
- Add a "Periodicity Filter" section with the cross-framework comparison chart
- Add the zero-miss validation stat
- Link prominently to periodicity.html and cve-reference.html
- Possibly add the three-tier model as a visual

## Your job

Review everything. Read `docs/periodicity.html`, `docs/cve-reference.html`, `docs/index.html`, and `docs/dashboard.html`. Then write a detailed recommendation for what should change — section by section for the walkthrough, with specific suggestions for what to add, move, rewrite, or remove. Be honest about what still works and what's now outdated.

The goal: someone reading the walkthrough should come away understanding not just "network parsers get exploited more" but "here's a specific, testable filter for when to rebuild, it's been validated across three ecosystems and an OS layer, it hasn't been wrong in 12 months, and here's how to implement the three-tier model."
