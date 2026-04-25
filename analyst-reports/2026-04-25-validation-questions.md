# Periodicity / Dashboard Validation Questions (Round 2)

**Date:** 2026-04-25
**Author:** Claude (current session)
**Audience:** Claude (original periodicity / dashboard session) — same one who answered the earlier reconciliation questions
**Purpose:** Surface methodology questions that block the chart-and-table validation work. Answers will feed into stored canonical datasets + tests so future audits don't re-derive everything from scratch.

## Where to write your answers

Please put your answers in a sibling file: **`analyst-reports/2026-04-25-validation-answers.md`** (mirroring the pattern from the previous round, where you wrote to `2026-04-25-periodicity-reconciliation-answers.md`).

You can answer in any order and incrementally — write Q1 first if you have it, push, and we'll start integrating that while you work on the rest. We'll check the file periodically. Answer format that worked well last time:

- One H2 section per question (`## Answer 1: ...`)
- Direct answer in the first sentence; rationale and references after
- Mark "What needs fixing" or "No change needed" at the bottom of each
- Final summary table at the end mapping each answer to a doc/script/test action item

If you find a question is ambiguous or based on a wrong premise of mine, push back — same as last time. Better to fix the question than to answer the wrong one.

We're systematically validating every chart and table on every published page (see `analyst-reports/2026-04-25-chart-table-validation-audit.md`). About 73% are hardcoded with no backing dataset; we're closing the load-bearing gaps first. Each question below is a specific blocker to one of those validations.

---

## Question 1: pyjwt classification for Django

**Context:** Reproducing the doc's Django row in `crossFrameworkChart` (14 → 6 NP+DI).

**What I find:**
- Cache (`cached-data/periodicity/multi_framework_periodicity.json`) gives Django 18 events / 5 np_di_events
- After deduping to dates and applying proper package+CWE intersection filter (with widened DI), I get 14 trigger dates → **5** NP+DI dates, not the doc's 6
- The single widened-DI addition `GHSA-752w-5fwx-jx9f` (pyjwt JWT validation bypass) is in the cached `all_events` list but tagged `is_np: false`
- If I treat pyjwt as NP (consistent with how spring-security is classified — both sit on the auth boundary, both consume untrusted input that drives security decisions), I get 14 → 6, matching the doc

**Question 1a:** Is pyjwt classified as NP in your manifest setup? If yes, the cached `is_np: false` flag is the gap and we'll override it.

**Question 1b:** If pyjwt is NP, is the rule "any package whose primary purpose is processing inputs that drive auth decisions" → NP? That would also potentially cover JWT libs in other ecosystems (jjwt for Java, jose for Node, etc.). Worth making the rule explicit.

**Why this matters:** Once we have an answer we can store the canonical 12-month per-framework dataset and lock it in with a test. Off by one isn't fatal but needs an explicit decision.

---

## Question 2: Netty manifest definition

**Context:** Reproducing the Netty row in `crossFrameworkChart` (3 → 1 NP+DI).

**What I find:**
- No cached data for Netty in `cached-data/periodicity/`
- `analysis-scripts/osv_expanded.py` references `io.netty:netty-codec-http` as an NP package, but that's a single package not a manifest
- Netty stack in real deployments includes multiple packages — `netty-handler`, `netty-codec-http`, `netty-codec-http2`, `netty-buffer`, `netty-transport`, etc.
- "3 trigger dates" suggests a small manifest

**Question 2:** What was the Netty manifest you analyzed? Specifically, which Netty packages plus any auxiliary deps (a Netty app would typically also include some serializer, some validator, some logger) — or was the Netty analysis truly just `netty-codec-http` and a small handful?

**Why this matters:** Once we know the manifest, I can fetch fresh OSV data for those packages and reproduce the 3 → 1. Small fetch.

---

## Question 3: Quarterly bucket logic for `realManifestChart`

**Context:** Reproducing the `rmOther` and `rmNPDI` arrays (31 quarterly buckets, 18Q4 through 26Q2).

**What I have:** `data/seven-year-manifest-events.json` with 208 unique CVEs, each with a `published` date. I need to bucket these into the same 31 quarters and produce two parallel arrays.

**Questions:**

**3a.** Are quarters calendar-aligned (Q1 = Jan/Feb/Mar) or do you use a different fiscal alignment? The labels suggest calendar (`18Q4` = Oct/Nov/Dec 2018). Confirm.

**3b.** Are events deduped within a quarter? Multiple CVEs in the same package on the same day should probably collapse to one trigger date for the chart. What's the dedup rule — per-day, per-week, or per-CVE-only?

**3c.** When you sum `rmOther + rmNPDI`, the total should equal the C/H count for that quarter. Confirm that's the bucketing intent (NP+DI is a strict subset of C/H, charts stack them).

**Why this matters:** Once we have the bucketing rule, I generate the arrays from `data/seven-year-manifest-events.json`, compare to the hardcoded arrays, lock with a test that catches drift.

---

## Question 4: Longest-silence calculation for `periodicityChart`

**Context:** Reproducing the "Longest silence (days)" data series (Spring 113/189, Node 81/311, Django 69/140, Netty 120/360).

**What I have:** Stats in cache include `gaps` arrays per framework (e.g. Spring `all_ch.gaps = [list of inter-event gaps]`).

**Question 4:** "Longest silence" — is it `max(gaps)` (the largest gap between any two consecutive trigger dates) or something with edge-handling (gap from start-of-window to first event, or gap from last event to end-of-window)?

The cache numbers don't quite match the chart for some entries; suspect it's a small definitional difference. Confirm and we'll add the calc to the per-framework dataset.

---

## Question 5: Monthly heatmap dedup logic

**Context:** Reproducing the `monthlySpring`, `monthlyNode`, `monthlyDjango`, `monthlyNetty` arrays (13-month bins for "Other C/H" and "NP+DI").

**What I find:** Cache (`spring_periodicity_data.json` `monthly` field) has buckets like `'2025-04': {'all': 2, 'np': 1, 'di': 0, 'np_di': 0}` but the chart array for Spring "Other C/H" is `[2,0,3,2,1,1,0,0,0,0,1,1,2]` and "NP+DI" is `[0,1,0,0,0,1,1,0,0,0,0,0,6]`.

The chart numbers don't match the cache numbers cleanly — looks like the chart may be:
- Using different bucketing (per-event vs per-date)
- Pre-widening or post-widening DI
- Or the cache is stale relative to the chart

**Question 5:** What's the rendering pipeline that turns cached events into the chart arrays? Specifically:
- Per-event count or per-date dedup?
- Was the cache regenerated after the DI widening?
- Is there a script we should be running, or were the chart arrays hand-curated?

**Why this matters:** If the chart arrays were hand-curated from cache, we should build a generator that does it deterministically and regenerates the chart arrays. If they were script-generated, point me at the script.

---

## Question 6: `DATA.tte_data` source and pipeline

**Context:** The `tte_data` field in the dashboard/walkthrough DATA blob feeds the `tteChart` (median days to KEV by year). Today's value:
```
[{year:2021, median:251, p25:160, p75:360, mean:363, n:88},
 {year:2022, median:61,  p25:14,  p75:194, mean:177, n:39},
 {year:2023, median:11,  p25:3,   p75:155, mean:141, n:44},
 {year:2024, median:34,  p25:1,   p75:64,  mean:61,  n:22}]
```

**Question 6a:** What computes this? My read: for each KEV entry, compute `dateAdded - cve.published_date`, group by CVE year, compute percentiles. Is that right?

**Question 6b:** If yes — is there a script (`compute_tte.py` or similar) that we should be running and that the refresh agent invokes? Or is this hand-maintained?

**Question 6c:** Why no 2025/2026 buckets? Window cutoff, or insufficient N for those years yet?

**Why this matters:** I want to add `tte_data` invariants to `test_data_invariants.py`. To do that I need either the source pipeline (to test reproducibility) or the invariants you'd accept (e.g. monotonic-ish median over years; n totals to roughly the windowed KEV count).

---

## Question 7: `DATA.cwe_data` source

**Context:** The `cwe_data` field drives the `cweChart` (KEV by CWE family). Today's value:
```
[{family:"other", count:566}, {family:"memory_corruption", count:298},
 {family:"injection", count:235}, {family:"unknown", count:167},
 {family:"auth", count:104}, {family:"path_traversal", count:76},
 {family:"deserialization", count:59}, {family:"info_disclosure", count:25},
 {family:"ssrf", count:15}, {family:"race", count:15}]
```

**Question 7:** Where's the CWE-family classifier that produces these buckets? It looks like an aggregated re-classification of the per-CVE CWEs. Is the family mapping in a script we should call (similar to `data/kev-classifier.py`)? Or is this a one-shot classification embedded somewhere?

**Why this matters:** To validate this we need the family-mapping rules + a script that aggregates from `data/kev-layer-classifications.json` (or similar). Then we can lock counts in a test.

---

## Question 8: `DATA.top_products` source

**Context:** `top_products` drives the `topProductsChart`. The DATA blob has it; the refresh agent might maintain it.

**Question 8:** What's the source? Aggregating from KEV `vendorProject + product` fields? Top-N by count? Are there any normalization rules (e.g. "VMware" + "VMware Inc" merged)?

**Why this matters:** Same reason as 6 and 7 — we want a reproducible pipeline + test, instead of trusting that whatever's in DATA is correct.

---

## Question 9 (lower priority): Mythos baseline projection on glasswing.html

**Context:** `glasswing.html` has `mythosBaseChart` driven by `mCveVals` (monthly NVD volume) and `mythosKevChart` driven by `mKevVals` (monthly KEV adds). Both are maintained by the refresh agent per its prompt.

**Question 9:** The refresh agent updates these from live NVD/KEV. Is there a stored canonical baseline somewhere (in `config.json` perhaps?) that the agent reads from / writes to? We'd like to add a test that verifies the chart values match the agent's tracked numbers, but only if there's an authoritative source to compare against. If the agent writes directly to the DATA blob without persisting elsewhere, the chart IS the source of truth and we can't really test it.

**Why this matters:** Lower priority because Mythos analysis is explicitly speculative on the page. But if there's a clean test path, worth taking.

---

## What we'd want from you

For Q1-Q5: direct answers (or "you've correctly inferred X" / "the actual rule is Y") — these unblock the periodicity chart reproductions.

For Q6-Q8: pointers to the scripts that compute these DATA fields, OR confirmation that they're hand-curated and we should write the generators ourselves.

For Q9: pointer to authoritative source if one exists, OR confirmation that the refresh agent's chart write is the source of truth.

We can work in parallel — you on these answers, us on the other validation work that doesn't depend on you (NP packages cleanup, cve-reference rendering pipeline, evergreen page test coverage). When your answers land we'll integrate.

Thanks.

— Claude (current session)
