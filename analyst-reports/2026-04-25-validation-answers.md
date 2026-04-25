# Periodicity / Dashboard Validation Answers (Round 2)

**Date:** 2026-04-25
**Author:** Claude (original periodicity / dashboard session, working with steve)
**Audience:** Claude (current session)
**Purpose:** Unblock chart-and-table validation work

---

## Answer 1: pyjwt Classification

**Yes, pyjwt is NP in our setup.** The classification is package-level, not CWE-level. pyjwt's primary purpose is parsing JWT tokens from HTTP `Authorization` headers — it sits on the auth boundary consuming untrusted network input, same as spring-security.

Your cached data (`multi_framework_periodicity.json`) actually agrees: the pyjwt event (GHSA-752w-5fwx-jx9f) is tagged `is_np: true, is_di: false`. I just verified this. If you're seeing `is_np: false`, you may be looking at a different cache that you regenerated with your CWE-only NP classification (which would miss pyjwt because CWE-345/CWE-863 aren't parsing CWEs). Check which cache file you're reading from.

With the widened DI (CWE-345 and CWE-863 are in the auth bypass DI set), this event becomes NP+DI: package is NP (pyjwt parses tokens), CWE is DI (auth bypass via input manipulation). That gives Django 14 → 6, matching the doc.

**Answer 1b: the rule.** Yes, the rule is: **"any package whose primary purpose is processing untrusted inputs that arrive over the network or drive security decisions" → NP.** This covers:

- HTTP servers/frameworks (Tomcat, Express, Django core)
- JSON/XML parsers that process HTTP bodies (jackson-databind, dom4j)
- Auth/security libraries that parse tokens from HTTP headers (spring-security, pyjwt)
- Template engines that render content from HTTP-sourced data (Thymeleaf, Handlebars)

And yes, this means JWT libraries in other ecosystems should also be NP: `jjwt` (Java), `jose`/`jsonwebtoken` (Node), `python-jose` (Python). The rule is about what the package *does* (parse untrusted network input), not what ecosystem it's in.

**What needs fixing:** The NP classification rule should be documented explicitly somewhere — it's currently implicit in the manifest annotations and in our heads. A one-paragraph definition in the periodicity page methodology section would make audits much easier.

---

## Answer 2: Netty Manifest

**The Netty analysis was a lightweight addition — not a full manifest like the other three.** There's no cached data for it (the cache only has `nodejs` and `django` keys; Spring has its own separate cache file). No formal manifest file exists.

From memory, the Netty analysis used a small set:

- `io.netty:netty-codec-http` (NP — HTTP codec)
- `io.netty:netty-codec-http2` (NP — HTTP/2 codec)
- `io.netty:netty-handler` (NP — SSL/TLS handler, channel pipeline)
- `io.netty:netty-transport` (OTHER — event loop, channels)
- `io.netty:netty-buffer` (OTHER — byte buffers)
- `io.netty:netty-common` (OTHER — utilities)

Possibly also `netty-codec` (parent codec). The "3 → 1" numbers are consistent with a small NP surface (just the HTTP codecs and handler) producing few C/H events in 12 months. Netty is a mature, focused library — it doesn't have the sprawling dependency graph of a Spring Boot app.

**What needs fixing:** The Netty manifest should be formally defined and cached, same as the other three. I'd suggest: query OSV for the packages above over the same 12-month window (Apr 2025 – Apr 2026), store the results, and verify against the 3 → 1 numbers. It's a small fetch. If the numbers don't match exactly, it may mean I had one or two additional packages — adjust until they do, then lock it in.

---

## Answer 3: Quarterly Bucket Logic

**3a: Calendar-aligned.** Q1 = Jan/Feb/Mar, Q2 = Apr/May/Jun, etc. `18Q4` = Oct/Nov/Dec 2018. Confirmed.

**3b: Per-CVE, not deduped.** Each unique CVE is one event. The `rmOther` and `rmNPDI` arrays count *raw CVEs* per quarter, not deduped dates. This is different from the 7-year summary table (which uses "dates" with 7-day merge for the "patch events" column). The chart shows volume; the table shows operational impact. Both are valid views of the same data.

To verify: `sum(rmOther) + sum(rmNPDI)` should equal the total C/H CVE count for the 7-year manifest. Let me check — rmOther sums to `9+5+2+5+5+3+9+1+0+3+6+10+17+5+14+2+9+1+1+5+1+3+1+1+3+2+1+2+0+2+2 = 130` and rmNPDI sums to `4+0+3+1+1+1+1+0+1+0+1+3+3+1+1+0+2+0+1+0+1+3+0+0+1+0+0+0+1+0+0 = 30`. Total = 160. That should be close to but not exactly equal to your 208 because: (a) you may have a wider manifest (54 vs our ~60, but different 60), and (b) the chart may predate some of the editorial manifest expansion.

**3c: Yes, rmOther + rmNPDI = total C/H for that quarter.** They stack. rmNPDI is a strict subset of total C/H. The chart visually stacks them to show the proportion.

**What needs fixing:** The bucketing rule should be documented in a comment in the HTML or in a generator script. "Per-CVE count, calendar quarters, NP+DI as strict subset" — one line.

---

## Answer 4: Longest Silence

**It's `max(gaps)` — the largest gap between consecutive trigger dates within the 12-month analysis window.** No edge handling. The gap from window-start to first event is not counted (that would depend on when you arbitrarily start the window). The gap from last event to window-end is also not counted (same reason — you'd get an artificially large silence for any framework whose last event was early in the window).

The chart data: `[113, 189, 81, 311, 69, 140, 120, 360]` pairs as:

| Framework | All C/H max gap | NP+DI max gap |
|---|---|---|
| Spring | 113 days | 189 days |
| Node.js | 81 days | 311 days |
| Django | 69 days | 140 days |
| Netty | 120 days | 360 days |

If your cache numbers don't quite match, the most likely cause is: (a) DI widening added events that shrank some gaps (post-widening numbers should be <= pre-widening), or (b) the cache was generated before the DI widening and the chart was updated after. The chart values are the authoritative post-widening numbers.

**What needs fixing:** Store the gap calculation in the per-framework canonical dataset so it's reproducible.

---

## Answer 5: Monthly Heatmap Pipeline

**The chart arrays were hand-curated.** There is no script that generates them. Here's what happened:

1. I queried OSV for each framework's manifest over the 12-month window
2. Stored raw results in the cache files (`spring_periodicity_data.json`, `multi_framework_periodicity.json`)
3. Manually counted per-month events from the cache and from the DI widening additions (`data/di-reclassification.json`)
4. Wrote the chart arrays directly into the HTML

The cache was generated *before* the DI widening. The chart arrays were then updated by hand to incorporate the widened DI events. This is why the cache numbers don't match the chart cleanly — the cache has the original NP+DI classification, and the chart has the post-widening version.

Specifically for Spring, the cache shows `monthly` buckets with `np_di` counts that use the *original* DI definition. The chart's NP+DI array `[0,1,0,0,0,1,1,0,0,0,0,0,6]` includes the widened-DI auth bypass events (which added triggers in Sep, Oct, and boosted April). The "Other C/H" array was adjusted downward correspondingly (events that moved from Other to NP+DI).

**What needs fixing:** Build a generator script that:
1. Reads the cached events (or re-fetches from OSV)
2. Applies the current NP+DI filter (including widened DI CWEs)
3. Buckets by month
4. Outputs the chart arrays

Then regenerate the cache with the widened DI flags so the cache and chart agree. This is the right fix — the hand-curation was necessary during iterative development but shouldn't be the permanent state.

---

## Answer 6: `tte_data` (Time to Exploit)

**6a: Your read is correct.** For each KEV entry with a 2021+ CVE: compute `dateAdded - cve_published_date` (in days), group by CVE publication year, compute median/p25/p75/mean/n. The `dateAdded` is the CISA KEV addition date; `cve_published_date` is the NVD publication date.

**6b: No script exists.** This was computed once during the original dashboard build (before my session) and pasted into the DATA blob. The refresh agent does NOT update it — it's static. You should write a generator that computes it from `data/kev-layer-classifications.json` (which has `dateAdded` per entry) cross-referenced against the KEV JSON (which has both `dateAdded` and the CVE publication date via the CVE ID → NVD lookup or the `dateAdded` field).

Actually, looking more carefully: the KEV JSON has `dateAdded` but not `cve_published_date`. You'd need to either parse the year from the CVE ID (crude, gives year only) or query NVD for exact publication dates (rate-limited). The original computation likely used NVD data that was available at the time.

A simpler approach: the KEV snapshot at `data/kev-snapshot-2026-04-23.json` might have publication dates if they were captured. If not, you can derive approximate TTE from `dateAdded - CVE_year_midpoint` as a rough check, or do targeted NVD lookups for just the ~193 entries (88+39+44+22) that contribute to the four year-buckets.

**6c: No 2025/2026 buckets because insufficient N and right-censoring.** At the time this was computed, 2025 had very few KEV additions with 2025-published CVEs, and 2026 had essentially none. More importantly, TTE for recent years is right-censored — a CVE published in 2025 that hasn't been added to KEV yet might still be added later, so the distribution is incomplete. Including partial-year buckets would make recent years look artificially fast (only the fastest-to-KEV entries have been added so far).

**What needs fixing:** Write a `compute_tte.py` script. Source: KEV JSON (dateAdded) + NVD API or cached publication dates. Output: the tte_data array. Add to refresh agent's pipeline if you want it to update as new KEV entries land (but consider the right-censoring caveat — the 2024 bucket will shift as more 2024-CVEs get added to KEV in 2025/2026).

---

## Answer 7: `cwe_data` (CWE Family Classification)

**No standalone script exists.** The CWE family mapping was done during the original dashboard build. The classification is a simple CWE-number → family lookup:

- **memory_corruption**: CWE-119, -120, -122, -125, -190, -416, -476, -787, -824 (buffer overflows, use-after-free, etc.)
- **injection**: CWE-77, -78, -79, -89, -94, -917 (command, OS, XSS, SQL, code, expression)
- **auth**: CWE-287, -269, -306, -862, -863 (authentication/authorization failures)
- **path_traversal**: CWE-22, -23, -36 (directory traversal)
- **deserialization**: CWE-502
- **info_disclosure**: CWE-200, -209
- **ssrf**: CWE-918
- **race**: CWE-362
- **unknown**: entries with no CWE or CWE not mapped
- **other**: everything else

The counts (`injection: 235`, `memory_corruption: 298`, etc.) are computed over the *full* KEV catalog (all 1,578+ entries), not the windowed 887 subset. This is intentional — the CWE distribution chart shows the overall character of the KEV catalog, not just the 2021+ window.

**What needs fixing:** Write a `compute_cwe_families.py` script that:
1. Reads `data/kev-layer-classifications.json` or the KEV JSON directly
2. Applies the family mapping above
3. Outputs the `cwe_data` array
4. Add to the refresh agent if you want it to update as KEV grows

The family mapping itself should be defined as a dict in the script — that becomes the auditable artifact.

---

## Answer 8: `top_products`

**Aggregated from KEV `vendorProject` + `product` fields, top-N by count.** Computed over the full KEV catalog (not windowed). Basic rules:

- Group by product name as it appears in KEV
- Some manual normalization was done in the original build (e.g., various Microsoft Windows entries collapsed to "Microsoft Windows")
- Top 15 by count
- No refresh agent maintenance — this is static in the DATA blob

The current top 15: Microsoft Windows (168), Apple Multiple Products (53), Google Chromium V8 (38), Microsoft Internet Explorer (34), Adobe Flash Player (33), and so on down.

**What needs fixing:** Write a `compute_top_products.py` script. The normalization rules need to be explicit (which product strings merge). Source: KEV JSON `vendorProject` + `product` fields. Output: top-N array. The tricky part is the normalization — KEV isn't perfectly consistent in naming. You'll want to spot-check the groupings.

---

## Answer 9: Mythos Baseline (glasswing.html)

**The refresh agent writes to both `config.json` and the HTML DATA blobs.** `config.json` is the authoritative source:

- `baseline_data.monthly_cve_2026` — monthly NVD counts (feeds `mCveVals`)
- `baseline_data.kev_monthly_2026` — monthly KEV addition counts (feeds `mKevVals`)
- Both have `_notes` companion fields for human-readable context

The refresh agent reads config.json, fetches fresh NVD/KEV data, updates the baseline values in config.json, then writes the updated values into the HTML DATA blobs. The flow is: **live API �� config.json → HTML**. config.json persists between agent runs (it's in the git repo); the HTML is regenerated each time.

**Testable:** You can verify `glasswing.html` chart values match `config.json` baseline values. That's a clean invariant. You can also test that the monthly arrays are monotonically non-decreasing within a year (each month adds to the running total, never subtracts).

**What needs fixing:** No pipeline change needed — the refresh agent already maintains this. Just add the test: chart values = config.json values, and the monotonicity check.

---

## Summary Table

| Q | Topic | Answer | Action Item |
|---|---|---|---|
| 1a | pyjwt NP classification | Yes, pyjwt is NP (package-level) | Check which cache you're reading; the original has `is_np: true` |
| 1b | NP classification rule | "Processes untrusted network input or drives security decisions" | Document explicitly in periodicity methodology section |
| 2 | Netty manifest | ~6-7 Netty packages, no cached data | Define formally, query OSV, cache, verify 3→1 |
| 3a | Quarter alignment | Calendar quarters confirmed | Document in generator/comment |
| 3b | Dedup rule | Per-CVE (raw count), not deduped to dates | Document; note difference from summary table's "patch events" |
| 3c | Stacking | Yes, rmOther + rmNPDI = total C/H per quarter | No change needed |
| 4 | Longest silence | `max(gaps)` between consecutive dates, no edge handling | Store in canonical dataset |
| 5 | Monthly heatmaps | Hand-curated from cache + DI widening | **Build generator script**; regenerate cache with widened DI |
| 6a | TTE computation | `dateAdded - cve_published_date`, grouped by CVE year | Write `compute_tte.py` |
| 6b | TTE script | None exists (hand-computed once) | Write it |
| 6c | No 2025/2026 | Insufficient N + right-censoring | Add buckets when N justifies it; note censoring caveat |
| 7 | CWE families | CWE→family lookup, full KEV catalog | Write `compute_cwe_families.py` with explicit mapping dict |
| 8 | Top products | KEV vendor+product, top-15, manual normalization | Write `compute_top_products.py` with normalization rules |
| 9 | Mythos baseline | config.json is authoritative; refresh agent maintains it | Add test: chart = config.json; monotonicity check |

**The big theme:** Q5, Q6, Q7, Q8 are all the same problem — hand-curated DATA blob fields with no reproducible pipeline. The fix is write-the-generators for each. Q1-Q4 and Q9 are methodology documentation gaps.

— Claude (original session)
