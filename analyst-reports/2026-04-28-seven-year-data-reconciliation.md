# 7-Year Manifest Backtest — Data Reconciliation Audit

**Date:** 2026-04-28
**Author:** Claude (forensic audit pass)
**Question:** Three sources publish three different headline counts for the 7-year manifest backtest. Which is canonical and how did they diverge?

---

## TL;DR

**The prose is the correct authored intent. The chart and data file are the divergent ones, for entirely different reasons:**

- **Chart `rmOther`/`rmNPDI` arrays** (160 / 30) are stale — last computed 2026-04-22 against the 48+6=54-pkg cache, were left in place across two later refactors, and have *never been regenerated* against the user-supplied 60-pkg / 176-version manifest the prose now describes.
- **`data/seven-year-manifest-events.json`** (175 / 34) is reproducible from a real OSV cache, but the cache itself is the *54-package script-derived manifest* (the 48 from `spring_manifest_analysis.py` + 6 editorial overrides for log4j/xstream/activemq), NOT the 60-pkg / 176-version production manifest.
- **Prose §7** (223 / 46 / 49 / 20 / 13) is hand-curated against the 60-pkg / 176-version manifest the user supplied on 2026-04-26 (commit `dc972d2`). These numbers are *hardcoded* in `scripts/build_hacker_tier_data.py` as `SEVEN_YEAR_PER_YEAR` / `SEVEN_YEAR_PER_QUARTER` Python literals — they are not derivable from any committed cache because that cache was never built.

So: the prose is what the user wants the page to say. The data file is a *narrower* reproducible reproduction. The chart is leftover from an even narrower predecessor of the data file.

---

## Sources, headline numbers, and provenance

| Source | C/H | NP+DI raw | NP+DI+DQ | Hacker S+A | Exploited | Manifest | Last touched | Reproducible? |
|---|---|---|---|---|---|---|---|---|
| **Chart `rmOther+rmNPDI`** in `docs/periodicity.html:1029-1030` | 160 | 30 | n/a | n/a | n/a (8 stars) | 48-pkg synthetic + log4j/xstream/activemq overrides; no DI-widening rebuild | `2af1344` (2026-04-28, exploit-marker restore only) — values date to `6b0ddb6` (2026-04-22) bumped at `83af848` (2026-04-23 DI widen) | No script. Closest predecessor was `data/seven-year-quarterly.json` at older snapshot |
| **Page prose §7** in `docs/periodicity.html:351, 375, 386-391` | 223 | 46 | 49 | 20 | 13 | "60 unique packages across 176 version-pinned entries" — user-supplied production estate | `efc8f3d` (2026-04-26) | Hardcoded as Python literals in `scripts/build_hacker_tier_data.py:230-251` (`SEVEN_YEAR_PER_YEAR`, `SEVEN_YEAR_PER_QUARTER`, `STRATEGY_EFFICIENCY_7YR`). Round-trips through `data/integrated-page-aggregates.json` |
| **`data/seven-year-manifest-events.json`** | 175 | 34 | 37* | 16* | 11 | 54 packages from `data/_manifest-osv-cache.json` (48 script + 6 editorial overrides) | `a12f8ba` (2026-04-25) | Yes — `scripts/build_seven_year_manifest_events.py` regenerates from `_manifest-osv-cache.json`; covered by `--check` mode but **not yet by `tests/run.sh`** |

\* The data file does not split DQ-rescue or hacker tier counts; the 37 / 16 figures come from cross-referencing with `data/hacker-tiers.json` and the prose's per-event detail table.

The chart's 8-star exploit overlay is itself yet a fourth count — it lists 9 distinct CVEs but plots them in 8 quarter buckets (Log4Shell + 45046 share Q11, Q1 2022). The prose claims 13 exploits including 2 pre-2018 Tomcat HTTP PUT events that the chart deliberately omits (axis starts 18Q4). After accounting for the 2017 pair, the chart's overlay reaches 11 — within 2 of the 13.

---

## Disagreement-by-disagreement

### 1. C/H total: 223 vs 175 vs 160

**Root cause:** different manifests.

- **Prose 223** comes from the user-supplied 60-pkg / 176-version production estate, hand-curated in commit `dc972d2` (2026-04-26). Commit message: *"Spring 4-5.x, Spring Boot 2.2-2.7, log4j 1.x + 2.x, XStream, ActiveMQ, Apache CXF, MINA, SSHD, Hazelcast, plus Maven/plexus/surefire build tooling and Groovy/JRuby/Jython scripting runtimes."* No backing cache or OSV query was ever committed.
- **Data file 175** comes from `data/_manifest-osv-cache.json` — 54 packages: the 48 from `analysis-scripts/spring_manifest_analysis.py` (real Spring Boot 3.x portfolio filtered to "has produced a CVSS 9+ advisory") plus 6 editorial NP-overrides (log4j-core/api, xstream, activemq broker/client/core).
- **Chart 160** is the same 54-pkg manifest as the data file but at an earlier OSV cache snapshot — the totals were authored at commit `6b0ddb6` (2026-04-22) before the DI-widening rebuild (`83af848` on 2026-04-23 only bumped the NP+DI count by +5; the totals stayed at 160). The cache has since grown by 15 events without the chart catching up.

**Recommended canonical:** the *prose* number (223) is the authored intent, but it is unbacked by any reproducible cache. The data file (175) is the only number with a `--check`-validated regen pipeline. The chart (160) has no reason to exist at this point.

### 2. NP+DI raw: 46 vs 34 vs 30

**Root cause:** same manifest difference as above; both also affected by the DI-widening (CWE-287/289/306/345/693/863/1321 added 2026-04-23 — `83af848`). The chart's +5 bump (25→30) at that commit was a hand-edit; the data file regenerated against the new DI set; the prose was authored after.

The 13-event gap between prose 46 and data file 34 traces almost entirely to packages that exist in the prose's 60-pkg manifest but not in `_manifest-osv-cache.json`: Apache CXF, MINA, SSHD, Hazelcast, plus the build-tooling layer (Maven core, plexus, surefire) and scripting runtimes (Groovy, JRuby, Jython).

### 3. NP+DI + DQ: 49 vs n/a vs n/a

**Root cause:** "DQ" (the renamed AI-scan tier) is a *post-NP+DI* manual review pass that promotes 3 specific events: Ghostcat (CVE-2020-1938), Tomcat partial-PUT (CVE-2025-24813), and ActiveMQ Jolokia (CVE-2026-34197). The +3 from raw NP+DI to NP+DI+DQ matches across both prose and data file — the difference is which raw NP+DI base they're added to. There is no DQ field in `data/seven-year-manifest-events.json`; the chart has no DQ axis at all.

### 4. Hacker S+A: 20 vs n/a vs n/a

**Root cause:** authored in commit `efc8f3d` from manual aggregation of 5 ranking rounds (R3 Java/Spring 175-event, R5 WAF-aware re-rank, R7 pre-2018 backfill for the 2017 pair, plus R4/R6 for non-Spring frameworks not in scope here). The "20" sums per-year `hacker_sa` counts in `SEVEN_YEAR_PER_YEAR`. Round R5's tier distribution table closes with "S (8-9), A (~20)" — so the operator's own R5 estimate is ~28-29 S+A events, not 20. The 20 is the subset of S+A judgments inside the 60-pkg / 7-year window, not the full 175-event corpus.

The chart and data file simply have no hacker tier dimension.

### 5. Exploited: 13 vs 11

**Root cause:** explained correctly in prose footnote — the 2 missing events are CVE-2017-12615 / CVE-2017-12617 (Tomcat HTTP PUT 2017 pair). They fall outside the data file's 2018-01-01 floor and outside the chart's 18Q4 axis, but the prose includes them because their KEV/EDB records landed inside the window (2018, 2022).

**Surprise extra:** the data file's 11 exploited includes **CVE-2023-46604** (ActiveMQ Classic OpenWire RCE, KEV+MSF, published 2023-10-27). The prose's 2023 row reports **0 exploited**. So the prose is implicitly *excluding* an event the data file flags as exploited NP+DI — likely because activemq-classic is not part of the 60-pkg manifest's ActiveMQ entries (which are broker/client/core but not the OpenWire-shipping classic 5.x). This is unflagged in the prose and merits a footnote.

### 6. Per-year sums (prose §7 table) cross-check

Prose totals (16 + 26 + 38 + 46 + 46 + 17 + 15 + 10 + 9) = **223**, NP+DI (4+8+4+10+7+3+4+4+2) = **46**, NP+DI+DQ = **49**, Hacker S+A = **20**, Exploited = **13**. Internally consistent.

Data file per-year (8 + 24 + 29 + 40 + 21 + 15 + 15 + 13 + 10) = 175, NP+DI (1+7+1+9+4+2+3+3+4) = 34. Internally consistent.

The two sets are *both* internally consistent; they describe *different manifests*.

### 7. `data/seven-year-quarterly.json` — orphaned middle layer

`scripts/build_seven_year_quarterly.py` reads the data file and aggregates it into 31 quarter buckets (sum 175 / 34). The on-disk file matches that. But the chart in `periodicity.html` *does not load this JSON* — it has its own `rmOther`/`rmNPDI` literals that don't match. So `seven-year-quarterly.json` is a phantom: it computes the right thing from the wrong source, and nothing renders it. The audit trail (`data/INTEGRATED-PAGE-AUDIT-TRAIL.md` line 92) explicitly flags this as an unfinished refactor item.

---

## Recommended canonical + fix plan

The prose is the user's authored intent and should drive the page. The fix is to make the supporting infrastructure agree, in the following priority order:

### Priority 1 — chart must match prose (blocking visual contradiction)

The chart sits literally above the prose claim "223 → 46 → 49 → 20 → 13". A reader summing the bars sees 160 and is misled. Either:

- **(a) Replace `rmOther`/`rmNPDI`** in `docs/periodicity.html:1029-1030` with values derived from `SEVEN_YEAR_PER_QUARTER` in `scripts/build_hacker_tier_data.py:222-227` (skipping the empty 18Q1-18Q3 buckets to recover the 31-bucket window). Sum-check: 223 / 49. New `rmOther` = `all_ch[3:] - npdi_ai[3:]` per quarter. **(Recommended, lowest-effort, locks chart and prose to the same hardcoded source.)**
- **(b) Keep the chart on the 175-event data file** by loading `data/seven-year-quarterly.json` at page load time, and amend the prose to "175 critical/high CVEs..." This is a much bigger edit (kills the user-supplied 60-pkg framing the prose was rewritten to support) and almost certainly not what's wanted.

### Priority 2 — make 223/46/49/20/13 reproducible from a committed cache

The prose numbers exist only as Python literals. Every future edit risks them drifting silently. Two options:

- **(a) Build a 60-pkg manifest cache.** Extend `data/_manifest-osv-cache.json` (or add a sibling) with the missing packages: CXF, MINA, SSHD, Hazelcast, the build-tooling layer, scripting runtimes. Re-run `scripts/build_seven_year_manifest_events.py` and verify totals = 223 / 46 / 49 (with DQ-rescue overlay). Replace the hardcoded `SEVEN_YEAR_PER_YEAR` literals in `build_hacker_tier_data.py` with a derive-from-events-file loop.
- **(b) Document the gap explicitly.** Add a footnote on §7 noting that the prose totals describe a wider production manifest (60 pkg / 176 entries) than the committed `_manifest-osv-cache.json` (54 pkg) and that the data file is a strict subset. Do NOT pretend reproducibility you don't have.

### Priority 3 — wire a test that prevents future drift

`tests/test_seven_year_npdi.py` covers the 24-package OSV-popular-libs dataset (a different artifact entirely — `seven-year-npdi-events.json`). Nothing tests the manifest events file or the chart arrays. Add:

```python
# tests/test_seven_year_manifest.py
- Assert scripts/build_seven_year_manifest_events.py --check passes
- Assert sum(rmOther) + sum(rmNPDI) == data['summary']['total_ch_events']
  AND sum(rmNPDI) == data['summary']['npdi_events']  (after Priority 1 lands)
- Assert SEVEN_YEAR_PER_YEAR['Total'] sums match its per-year rows
- Assert STRATEGY_EFFICIENCY_7YR['npdi_ai']['raw_triggers'] ==
        SEVEN_YEAR_PER_YEAR['Total']['npdi_ai']
```

Add to `tests/run.sh`. The CLAUDE.md rule says *"Expanding a page with a new numeric claim → add a test for it. Claims without tests rot."* These claims rotted.

### Priority 4 — fix the orphan exploited event

The prose 2023 row reports 0 exploited, but `data/seven-year-manifest-events.json` flags **CVE-2023-46604 (ActiveMQ Classic OpenWire RCE)** as NP+DI exploited. Either:
- Add it to the prose 2023 row (changes 0 → 1 exploited, 13 → 14 total), or
- Footnote that activemq-classic 5.x is not in the 60-pkg manifest (only activemq-broker / -client / -core 6.x are), so the OpenWire RCE is correctly excluded. Note that this is the same KEV-confirmed event Hacker R3 tiered S; excluding it deserves justification.

---

## Other things found while looking

1. **`SEVEN_YEAR_PER_QUARTER` arrays in `build_hacker_tier_data.py` have 34 buckets** (start 18Q1) but the rendered chart and §7 table window is 18Q4 onwards (31 buckets). The first 3 buckets are zeros, so the totals come out the same, but it's a small alignment hazard for any future test that doesn't account for the 3-bucket offset.

2. **`docs/periodicity.html:351` claims "60 packages across 176 version-pinned entries"**; **`docs/periodicity.html:1018` chart comment** says "Q4 2018 – Q2 2026" but the chart axis is 18Q4-26Q2 (31 buckets, no per-version sprawl). The 176-version distinction matters for the prose's "version sprawl" claim but is invisible in any aggregated count we have.

3. **Prose §7 efficiency table line 391** ("Union 11/13 caught, 39 patch events, 56 raw triggers") is consistent with `STRATEGY_EFFICIENCY_7YR['union_npdi_ai_hacker']`. Prose §3 line 388 line up with `npdi_raw` (34 / 46 / 6/13). Internally consistent within the hardcoded dict.

4. **`data/doc-canonical-npdi-events.json`** documents an *earlier* canonical position: 30 NP+DI events, 5 caught + 3 missed = 8 in-scope exploited. That number is now superseded by the 13 / 11 in the prose / data file. The file is dated 2026-04-25 and is referenced by `tests/test_cve_reference.py` for CVE-set membership only — not for headline counts. Worth retiring or marking superseded.

5. **The 2af1344 commit (today, 2026-04-28)** edited the chart purely to restore the exploit-marker overlay — it did not touch `rmOther`/`rmNPDI`. This means the bar-array drift has now survived two post-prose commits silently.

---

## Test result

`bash tests/run.sh` — all green (4773 + 178 + 53 + 69 + 46 + others). The current suite does NOT cover:
- Manifest events file freshness (no `--check` invocation in tests/run.sh)
- Chart array sums vs prose vs aggregates
- Cross-file consistency between `seven-year-quarterly.json` and the rendered chart

These gaps allowed the divergence to develop without a single red test.

---

## Key file paths

- `/sessions/bold-nice-euler/KEV-analysis/docs/periodicity.html` — chart at lines 1018-1093, prose at 351, 375, 386-391, table at 363-376
- `/sessions/bold-nice-euler/KEV-analysis/data/seven-year-manifest-events.json` — 175/34, generated `2026-04-25T10:31:44Z`
- `/sessions/bold-nice-euler/KEV-analysis/data/seven-year-quarterly.json` — 175/34 quarterly aggregation, orphaned (not loaded by chart)
- `/sessions/bold-nice-euler/KEV-analysis/data/integrated-page-aggregates.json` — 223/46/49/20/13 round-tripped from hardcoded literals
- `/sessions/bold-nice-euler/KEV-analysis/data/_manifest-osv-cache.json` — 54-package OSV cache, sha256 prefix `5cc4558f8fb9cd54`
- `/sessions/bold-nice-euler/KEV-analysis/scripts/build_seven_year_manifest_events.py` — produces the data file
- `/sessions/bold-nice-euler/KEV-analysis/scripts/build_hacker_tier_data.py:230-251` — hardcoded prose totals
- `/sessions/bold-nice-euler/KEV-analysis/scripts/build_seven_year_quarterly.py` — produces orphaned quarterly aggregator
- `/sessions/bold-nice-euler/KEV-analysis/tests/test_seven_year_npdi.py` — covers different (24-pkg-OSV) dataset; manifest events file is uncovered
- Key commits: `dc972d2` (60-pkg manifest pivot, 2026-04-26), `efc8f3d` (prose lands, 2026-04-26), `60165e5` (aggregates JSON materialized, 2026-04-26), `a12f8ba` (data file frozen, 2026-04-25), `6b0ddb6` (chart authored, 2026-04-22), `83af848` (DI widen +5 NP+DI on chart, 2026-04-23), `2af1344` (chart touched today without value update, 2026-04-28)
