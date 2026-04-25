# Chart and Table Validation Audit

**Date:** 2026-04-25
**Scope:** every chart and every table on every published page
**Question:** for each, is there a stored, reproducible source dataset that a test verifies?

## Status legend

- ✅ **Validated** — stored dataset in `data/`, generator script reproduces from cached inputs, test in `tests/` locks it in
- 🟡 **Partial** — dataset in cache or DATA blob, but no end-to-end test from raw inputs
- ❌ **Not validated** — hardcoded values inline, no stored source dataset, no test

---

## dashboard.html — 13 charts, 7 tables

### Charts

| Chart | Driven by | Status |
|---|---|---|
| `crossFrameworkChart` | hardcoded labels + values (14/5, 14/2, 14/6, 3/1) | ❌ |
| `chainingChart` | hardcoded inline | ❌ |
| `epssChart` | hardcoded inline | ❌ |
| `layerRateChart` | `DATA.layer_data` via `layerDisplay` | ✅ via `test_data_invariants.py` |
| `layerDistChart` | `DATA.layer_data` | ✅ |
| `dashLibDistChart` | `npCounts` from lib analysis | ❌ |
| `dashLibTopChart` | `top20` libraries | ❌ |
| `httpChart` | `DATA.http_data` via `httpSorted` | ✅ via `test_http_data.py` |
| `liftChart` | `DATA.http_data` via `httpSorted` | ✅ |
| `tteChart` | `DATA.tte_data` | 🟡 (field exists in DATA, no test) |
| `cweChart` | `DATA.cwe_data` via `cweDisplay` | 🟡 (field exists, no test) |
| `ransomwareChart` | `DATA.ransomware_data` | ✅ |
| `topProductsChart` | `DATA.top_products` via `tp` | 🟡 (field exists, no test) |

### Tables

| Table | Driven by | Status |
|---|---|---|
| Layer exploitation table | `DATA.layer_data` (also static HTML table) | ✅ via cross-page identity check |
| Time-to-exploit table | hardcoded (2021/2022/2023/2024 rows) | ❌ |
| Watch list (server-side) | `WATCH_LIST` JS object | ❌ (analyst maintains, no test) |
| Watch list (desktop) | `WATCH_LIST` JS object | ❌ |
| Thesis challenge | hardcoded body, currently empty | ❌ |
| Other prose-embedded tables | hardcoded | ❌ |

---

## index.html (walkthrough) — 12 charts, 21 tables

### Charts

| Chart | Driven by | Status |
|---|---|---|
| `docLayerChart` | `DATA.layer_data` via `layerFiltered` | ✅ |
| `docHttpChart` | `DATA.http_data` via `docHttpSorted` | ✅ |
| `docLibDistChart` | `npPct` from lib analysis | ❌ |
| `docLibTopChart` | `top25` libraries | ❌ |
| `docTteChart` | `DATA.tte_data` | 🟡 |
| `crossFrameworkChart` | hardcoded labels + values | ❌ |
| `funnelChart` | hardcoded `values` (filter funnel) | ❌ |
| `chainingChart` | hardcoded inline | ❌ |
| `docMythosBaselineChart` | `mythosCveVals` (NVD baseline) | 🟡 (refresh agent maintains) |
| `docMythosCveChart` | `mythosCveCounts` | 🟡 (refresh agent maintains) |
| `docMythosProjectionChart` | `baselineTrend` projection | ❌ |
| `docPatchVelocityChart` | `msPatches` (Patch Tuesday) | 🟡 (refresh agent maintains) |

### Tables

21 tables in the walkthrough. Most duplicate the DATA blob and are validated via cross-page identity. The non-DATA tables:

| Table | Status |
|---|---|
| Static layer table (lines 230-244) | ✅ (matches DATA blob via `test_data_invariants.py`) |
| Watch list tables (server + desktop, §11) | ❌ (analyst maintains) |
| Thesis challenge table (§11) | ❌ (currently empty) |
| Probable participant CVEs table | ❌ |
| Various inline prose tables | ❌ (all hardcoded) |

---

## periodicity.html — 8 charts, 15 tables

### Charts

| Chart | Driven by | Status |
|---|---|---|
| `crossFrameworkChart` | hardcoded `[14, 14, 14, 3]` and `[5, 2, 6, 1]` | 🟡 Spring + Node reproduced from cache; Django off-by-1 (pyjwt classification); Netty needs OSV fetch |
| `periodicityChart` | hardcoded events + longest-silence per framework | ❌ |
| `realManifestChart` | hardcoded `rmOther` + `rmNPDI` quarterly arrays (2018Q4–2026Q2) | 🟡 source data exists in `data/seven-year-manifest-events.json`; aggregation to quarterly arrays not yet generated |
| `monthlySpring` | hardcoded month-by-month arrays | 🟡 (cached in `spring_periodicity_data.json`) |
| `monthlyNode` | hardcoded | 🟡 (cached in `multi_framework_periodicity.json`) |
| `monthlyDjango` | hardcoded | 🟡 (cached) |
| `monthlyNetty` | hardcoded | ❌ (no Netty cache) |
| `chainingChart` | hardcoded (OS chaining + Spring trigger overlay) | ❌ |

### Tables

| Table | Status |
|---|---|
| Cross-framework summary | ❌ (matches chart, both hardcoded) |
| Monthly periodicity stats per framework | ❌ |
| Spring 7-year quarterly summary | 🟡 (data exists, no rendering pipeline) |
| **Full NP+DI CVE list** (30 entries) | ✅ extracted to `data/doc-canonical-npdi-events.json` |
| **Filter misses** (3 entries) | ✅ extracted to `data/doc-canonical-npdi-events.json` |
| EPSS comparison tables | ❌ (hardcoded EPSS scores per CVE) |
| Various other prose tables | ❌ |

---

## cve-reference.html — 0 charts, 2 tables

| Table | Status |
|---|---|
| Per-CVE classification table (large) | ✅ source is `data/kev-layer-classifications.json`; locked by `test_classifications.py`; rendering pipeline unverified but data is authoritative |
| Summary tiles (4 KPI tiles counted from DOM) | 🟡 derived from the large table |

---

## glasswing.html — 4 charts, 3 tables

All charts and tables on this page are **speculative analysis** (the page is labeled as such). Most are maintained by the refresh agent (NVD volume, KEV additions, Patch Tuesday) and the analyst agent (probable participant CVEs).

| Chart | Driven by | Status |
|---|---|---|
| `mythosBaseChart` | `mCveVals` (monthly NVD volume) | 🟡 (refresh agent updates daily; no test verifies it matches NVD source) |
| `mythosCveChart` | hardcoded vendors + counts | ❌ |
| `mythosKevChart` | `mKevVals` (monthly KEV adds) | 🟡 |
| `dashPatchChart` | hardcoded inline (Patch Tuesday) | 🟡 (refresh agent maintains; no test) |

| Table | Status |
|---|---|
| Confirmed Mythos finds (3 CVEs) | ❌ hardcoded, low-volume, manageable manually |
| Probable participant self-scan CVEs (4) | ❌ in `config.json`, not validated |
| Watch dates (announcement, Mythos preview, etc.) | ❌ |

---

## osv-exploitation.html — 0 charts, 13 tables

Scratch page. All tables derive from the OSV cached datasets in `cached-data/osv/` (osv_results.json — 79 packages; osv_expanded_results.json — 177; osv_cwe_results.json — 24 with detail). Tables are hand-written from the analysis but the underlying data is in cache.

| Status across the 13 tables | Mostly 🟡 (source in cache, no rendering test) |

---

## evergreen.html — 4 charts, 29 tables

Scratch page exploring evergreen-vs-frozen analysis for JVM, RHEL, Windows Server, Node.

| Chart | Driven by | Status |
|---|---|---|
| `jvmChart` | hardcoded by year | ❌ |
| `rhelChart` | hardcoded by year | 🟡 (refresh agent updates from stack.watch) |
| `winChart` | hardcoded by Windows Server version | ❌ |
| `nodeChart` | hardcoded by year | ❌ |

29 tables — almost all hardcoded numbers from RHEL errata, Windows Server lifecycles, Node release timelines. Most are ❌ because they're one-off research artifacts.

---

## build-mechanics.html — 0 charts, 3 tables

| Table | Status |
|---|---|
| Filter scope by auth posture (§12.2) | ❌ but it's a conceptual rule table, not a data table |
| Without-WAF / With-WAF gap table (§9) | ❌ same — conceptual |
| Triage decision flow output table (§12.5) | ❌ same — conceptual |

These three are operational rule tables, not data tables. They don't need a dataset; they need editorial review.

---

## Summary by status

| Status | Charts | Tables | Total |
|---|---:|---:|---:|
| ✅ Validated | 8 | ~5 | ~13 |
| 🟡 Partial (data exists, no test or no pipeline) | 11 | ~10 | ~21 |
| ❌ Not validated (hardcoded, no source) | 22 | ~75 | ~97 |
| **Total** | **41** | **~93** | **~134** |

Roughly **10% of the visual elements have stored datasets + tests; 16% have data but no test; 73% are hardcoded with no backing dataset.**

---

## Priority queue for validation

### High priority — load-bearing claims, partial-validation already

1. **`periodicity.html` `crossFrameworkChart`** — close out the 14→5/2/6/1 reproduction. Spring + Node done; Django needs pyjwt-as-NP fix; Netty needs OSV fetch. → Store as `data/twelve-month-per-framework.json`, add test.

2. **`periodicity.html` `realManifestChart` quarterly arrays** — `rmOther` and `rmNPDI` arrays. We have `data/seven-year-manifest-events.json`; aggregate to quarterly buckets and verify they match the hardcoded arrays. → Add test that catches drift between dataset and chart.

3. **`periodicity.html` `monthlySpring/Node/Django` heatmaps** — cached data exists in `cached-data/periodicity/`. Generate the monthly arrays from cache, add test, drop into stored dataset.

4. **`dashboard.html` + `index.html` DATA fields without tests:** `tte_data`, `cwe_data`, `top_products`. Add coverage to `test_data_invariants.py`. Refresh agent maintains these; we just need the test to lock them in.

### Medium priority — concrete deliverables, not load-bearing today

5. **`periodicity.html` `periodicityChart` (events + longest silence)** — derivable from the same per-framework data once we have it stored.

6. **`periodicity.html` `chainingChart` (OS chaining + Spring overlay)** — needs the OS periodicity dataset (`os_periodicity_data.json`) plus Spring trigger overlay aggregated. Test reproduces from cache.

7. **`evergreen.html` `rhelChart`** — refresh agent maintains; add test that verifies the chart matches the agent's data source.

8. **`glasswing.html` `mythosBaseChart` and `mythosKevChart`** — refresh agent maintains; add test for the data the agent writes.

### Low priority — scratch / speculative pages

9. **`osv-exploitation.html` 13 tables** — source data is in cache; if we want long-term reproducibility, generate each table from the cached JSON, add tests. But this is a scratch page, lower value.

10. **`evergreen.html` 29 tables** — mostly one-off research; not worth investment unless the page graduates to canonical status.

11. **`glasswing.html` confirmed/probable CVE tables** — analyst-maintained, low volume, manual oversight is probably enough.

### Out-of-scope — conceptual, no data behind them

- `build-mechanics.html` 3 tables (rule tables, not data)
- `dashboard.html` and `index.html` "thesis challenge" table (intentionally empty)

---

## Open methodology question

For tables that are currently hardcoded prose tables (e.g. EPSS comparison tables in periodicity.html, the inline tables in evergreen.html), the question is whether to:

**(a)** Generate them from stored datasets, like we did for the DATA blob spans → maintains a single source of truth, but requires generation pipeline per table.

**(b)** Leave them hardcoded but add a test that verifies the hardcoded numbers match a stored dataset → cheaper to add, doesn't require rendering pipeline.

**(c)** Accept them as one-off prose, no validation → fastest, accepts drift risk.

The DATA blob span approach (option a) was the right choice for the headline KPIs because they update daily. For low-frequency content (RHEL backtest, Windows Server lifecycles), option b might be sufficient.
