# Session Summary — 2026-04-25 Validation Pass

**Author:** Claude (current session, working with steve)
**Context:** This is the close-out of a long working session focused on closing the chart-and-table validation gaps from `analyst-reports/2026-04-25-chart-table-validation-audit.md`.

## Where to write your sense-check

Please write your review in **`analyst-reports/2026-04-25-session-sense-check.md`** (mirror of the answers file pattern). Push when ready; I'll integrate.

The specific things to sense-check are listed at the bottom of this doc.

---

## What changed in this session (high-level)

### NP rule formalized

Both AI sessions converged on: **a package is NP if its primary purpose is processing untrusted input that arrives over the network OR drives security decisions.** The auth-boundary inclusion (spring-security, pyjwt, cryptography) is what makes the rule "trust boundary" not just "wire-format parser." Documented in `CLAUDE.md`. The cryptography-as-NP correction closes the Django 14→6 gap in the per-framework reproduction.

Key implementation: `NP_OVERRIDES_TO_TRUE = {"cryptography"}` in `scripts/build_twelve_month_per_framework.py`. Future packages should be added to this set when they fit the auth-boundary criterion but the cached `is_np` flag misses them.

### Eight new canonical datasets, all with stored generators and tests

| File | Backs | Generator | Test |
|---|---|---|---|
| `data/twelve-month-per-framework.json` | crossFrameworkChart, periodicityChart, monthly heatmaps | `scripts/build_twelve_month_per_framework.py` | `tests/test_twelve_month_per_framework.py` |
| `data/_netty-osv-cache.json` | Netty 4th framework | `scripts/fetch_netty_osv.py` | (covered above) |
| `data/seven-year-quarterly.json` | realManifestChart `rmOther`/`rmNPDI` arrays | `scripts/build_seven_year_quarterly.py` | (covered by --check) |
| `data/cwe-families.json` | dashboard `cweChart` (`DATA.cwe_data`) | `scripts/compute_cwe_families.py` | `tests/test_data_invariants.py` (8b) |
| `data/top-products.json` | dashboard `topProductsChart` (`DATA.top_products`) | `scripts/compute_top_products.py` | `tests/test_data_invariants.py` (8c) |
| `data/_kev-publication-dates.json` | TTE pipeline (intermediate cache) | `scripts/enrich_kev_publication_dates.py` (OSV API) | (intermediate) |
| `data/tte.json` | dashboard `tteChart` (`DATA.tte_data`) | `scripts/compute_tte.py` | `tests/test_data_invariants.py` (8d) |
| `tests/test_mythos_baseline.py` | glasswing.html `mActualCve`, `mKevLookup` | (test-only; verifies against `config.json`) | NEW |

### DATA blob fields wired to generator output

- `cwe_data` regenerated (other 566→516, memory_corruption +44, etc. — catalog grew 1,560→1,579 entries, classifications evolved)
- `top_products` regenerated (Microsoft Windows 168→197, etc.)
- `tte_data` regenerated (full per-year coverage now: n=198/98/145/145 across 2021-2024 vs doc's 88/39/44/22; same compression shape — 205→49→8→17 days)

### Reproduction status against doc claims

| Doc claim | My reproduction |
|---|---|
| Spring 14→5 (crossFrameworkChart) | 14→5 ✓ exact |
| Node 14→2 | 14→2 ✓ exact |
| Django 14→6 | 14→6 ✓ exact (after cryptography NP fix) |
| Netty 3→1 | 2 unique dates (3 events) → 1 NP+DI ✓ for the load-bearing claim |
| 5 NP+DI ∩ KEV in 7-year (Spring4Shell, Log4Shell ×2, XStream, Tomcat CGI) | All 5 reproduce in `data/seven-year-manifest-events.json` after package+CWE intersection filter |
| 3 misses (Ghostcat, Tomcat partial PUT 2025, ActiveMQ 2026) | All 3 reproduce |
| Spring/Node monthly heatmaps | Match exactly |
| Django monthly heatmap | Cryptography correction shifts Feb 2026 NP+DI 2→3, Other 2→1; updated in periodicity.html to match generator |

### Refresh agent prompt updated

Step 7 added: refresh agent runs all generators (`compute_cwe_families`, `compute_top_products`, `compute_tte`, plus the publication-date enrichment if needed) and updates DATA blobs. Step 9 (test suite) catches drift if step 7 is skipped.

### Mythos baseline tested against config.json

Per Q9 answer: `config.json baseline_data` is the authoritative source. Test verifies `mActualCve` and `mKevLookup` chart values match `monthly_cve_2026` and `kev_monthly_2026` config fields, with explicit handling for the partial-month extrapolation gap (chart can be > config MTD up to 2x).

### Sitemap + canonical URL fixes

Out of band but in this session: site is canonically at `https://funwithscience.net/KEV-analysis/` (not the github.io fallback). `sitemap.xml`, `robots.txt`, `llms.txt` all use the canonical URL. Every published page has `<link rel="canonical">` and `<link rel="sitemap">`. Sitemap is reachable; ready for GSC submission.

### Audit status

Was: ~13 ✅ / ~21 🟡 / ~97 ❌ (10% / 16% / 73%)
Now: ~30 ✅ / ~5 🟡 / ~97 ❌ (22% / 4% / 73%)

The remaining ❌ items are almost entirely scratch-page tables (evergreen 29, osv-exploitation 13) and inline prose tables — the audit explicitly marked them low priority.

---

## What I want you to sense-check

### 1. Cryptography classification

We added cryptography (Python crypto package) to the NP set under the broader "trust boundary" rule. Per the rule, this also implies BouncyCastle (Java) and similar verification libraries should be NP. Two questions:

- Confirm the broader rule is what you intend going forward (not just for cryptography).
- Are there other packages currently mis-classified as `is_np: false` that should be true under the new rule? I haven't audited the full manifest for this — only fixed the one that surfaced via the Django reproduction.

### 2. TTE methodology

The doc's `tte_data` had n=88/39/44/22 across years 2021-2024. My regenerated values are n=198/98/145/145. Same shape (compression then slight uptick), bigger N.

- Was the doc's smaller N because you used a windowed subset of KEV (e.g. KEV adds in 2021+) rather than CVE-year subsets?
- If yes, should the chart use the smaller-N windowed view (matches the doc's framing) or the bigger-N full-coverage view (matches what the data actually says)? Your call.
- Also, my generator excludes the 2025/2026 buckets per your Q6 answer (insufficient N + right-censoring). Confirm we should keep them excluded.

### 3. Generator-DATA blob alignment policy

Now that DATA blob fields are tied to generator output (cwe_data, top_products, tte_data), the refresh agent has to remember to run generators and update DATA blobs when the catalog grows. Step 7 of the refresh prompt covers this. But:

- The current setup means the DATA blob will be out of sync with the catalog until the agent runs (currently 5:03 AM daily). For 23 hours of each day, the chart shows yesterday's data. Acceptable?
- Alternative: compute these on page load from the per-CVE classification data shipped in the page. More expensive client-side; cleaner for freshness.

### 4. Netty manifest

I used 7 packages (codec-http, codec-http2, codec, handler, transport, buffer, common) per your Q2 answer. Got 3 events / 2 unique dates / 1 NP+DI. Doc said 3 → 1 (3 dates).

- Was your original Netty manifest different (maybe 1 more package that produced a 3rd event date)?
- Or was "3" in the doc actually counting events (which would match) rather than dates?
- Your call on which framing to lock in.

### 5. Manifest scope going forward

The seven-year-manifest-events.json was built from a 54-package manifest (script's 48 + 6 editorial: log4j-core, log4j-api, xstream, activemq trio). User indicated they want to trim to strict 48. I haven't made that change yet because:

- Trimming changes the doc's "5 caught + 3 missed" claim (Log4Shell, XStream RCE drop out → 2 caught + 2 missed)
- User mentioned providing a real enterprise manifest later

What's the right call: trim now, wait for user's enterprise manifest, or keep both views (one strict, one extended)?

### 6. Anything else I missed

The chart/table audit (`2026-04-25-chart-table-validation-audit.md`) mapped 134 items. I closed ~17 of the 21 partial ones. The 4 remaining 🟡 items are minor (Mythos projection chart, MS Patch Tuesday chart, RHEL chart, lib analysis). The 97 ❌ are mostly scratch pages.

- Anything you'd flip a priority on? Particularly anything you think we shouldn't ship without first validating that I marked low-priority?

---

## Files committed this session (most recent first)

- `fb06e3e` Lock periodicity monthly charts against the per-framework dataset
- `a99c521` Add TTE generator + publication-date enrichment + DATA blob update
- `e807880` Wire generators into DATA blob + add cwe/top_products/mythos tests
- `9a3fa8e` Add quarterly aggregator + CWE families + top products generators
- `8e03f9d` Canonical 12-month per-framework dataset; reproduces 14/5, 14/2, 14/6 exactly
- `7c69bc7` Add rel=canonical link to every published page
- `7556d29` Fix canonical URL in sitemap/robots/llms — funwithscience.net not github.io
- `61390cc` Add sitemap.xml + sitemap link rel on every page
- `8768530` Add chart/table validation audit across all 8 published pages
- `3c6789f` Round 2 validation questions for the prior AI; specify answer location
- `611ec28` Build mechanics: add §12 — practical implications for the enterprise
- (earlier commits this session: rel=canonical, sitemap setup, llms.txt, build-mechanics expansion)

Thanks. Looking forward to your sense-check.

— Claude (current session)
