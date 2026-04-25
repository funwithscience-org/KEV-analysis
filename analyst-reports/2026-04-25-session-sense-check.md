# Session Sense-Check — 2026-04-25

**Author:** Claude (original periodicity / dashboard session, working with steve)
**Purpose:** Review the validation session's work and flag anything missed

---

## Overall Assessment

This is excellent infrastructure work. The eight canonical datasets with generators and tests close the biggest class of bugs we've had (hand-curated numbers drifting from source data). The twelve-month per-framework reproduction matching exactly (14/5, 14/2, 14/6) is strong evidence the methodology is sound. The refresh agent prompt update (step 7 generators, step 9 test suite) means this won't regress.

There is one significant issue with the seven-year quarterly data, and a handful of smaller items.

---

## Sense-Check 1: Cryptography Classification

**Confirmed.** The broader rule is what we intend going forward: "processes untrusted input that arrives over the network OR drives security decisions → NP." The auth-boundary expansion (spring-security, pyjwt, cryptography, bouncycastle) is the right move. The `NP_OVERRIDES_TO_TRUE` mechanism in `build_twelve_month_per_framework.py` is clean.

**Other packages to audit:** For the 12-month manifests, the likely candidates are:

- **Spring:** `spring-security-oauth2-resource-server` is already NP in the script manifest. `bouncycastle` (bcprov-jdk18on) is currently OTHER — should be NP if it's doing cert/signature verification on untrusted input. Check if it has any C/H events in the 12-month or 7-year windows. If not, the classification doesn't affect any numbers yet, but should still be corrected for consistency.
- **Node.js:** `jsonwebtoken` or `jose` if present — same logic as pyjwt. Check the Node manifest.
- **Django:** `cryptography` is now fixed. `python-jose` if present.

None of these are likely to change the headline numbers (they'd only matter if they have C/H events with widened-DI CWEs in the analysis window), but the audit should be done for correctness.

**No change needed** to the rule or the implementation. Just run the audit.

---

## Sense-Check 2: TTE Methodology

The N discrepancy (doc's 88/39/44/22 vs regenerated 198/98/145/145) is significant and I can explain it.

**The doc's smaller N was likely because the original computation used a different denominator:** it probably counted only KEV entries *added* in each year (i.e., dateAdded falls in 2021/2022/2023/2024), not KEV entries whose *CVE was published* in that year. Your generator groups by CVE publication year, which is the right approach for "time to exploit" — you want to know how long after a CVE is published before it reaches KEV.

But the original may have been answering a different question: "for entries added to KEV in year X, how old were they?" That would give smaller N per year-bucket because it only counts additions in that calendar year, not all CVEs from that publication year that were ever added.

**My recommendation:** Use your regenerated values (CVE-publication-year grouping, bigger N). The shape is the same (compression then slight uptick), and CVE-publication-year is the more defensible methodology for TTE. The doc's original values were a one-shot computation with no stored methodology — yours is reproducible and documented. Just note the methodology change.

**Keep 2025/2026 excluded.** Right-censoring is real and would mislead.

---

## Sense-Check 3: Generator-DATA Blob Alignment

**23-hour staleness is acceptable.** The dashboard already has a timestamp ("Data refreshed: ...") that tells the reader when the data was last updated. The charts show macro patterns (CWE distribution, top products, TTE compression) that don't shift meaningfully day-to-day. A new KEV entry might add 1 to "other" in the CWE chart, changing 516 to 517 — invisible in the bar chart.

**Don't compute on page load.** It would require shipping the full per-CVE classification data in the page (currently ~300KB compressed), adding JavaScript compute time on every load, and creating a new class of client-side bugs. The generator pipeline is the right architecture. The daily refresh agent is more than sufficient.

The one exception where freshness matters is the Glasswing page (Mythos tracking is time-sensitive), and that's already handled by the refresh agent updating config.json → HTML.

---

## Sense-Check 4: Netty Manifest

**"3" in the doc was likely events, not dates.** Your reproduction (3 events / 2 unique dates / 1 NP+DI) is consistent with what I recall. The Netty analysis was lightweight — I probably counted 3 events without deduping to dates, which is consistent with the chart treating per-CVE counts (same as the quarterly chart per Q3b).

**Lock in: 3 events → 1 NP+DI.** The chart already uses this framing (bars show event counts). The summary table on the periodicity page says "3" in the "All C/H dates" column — which is technically wrong if there are only 2 unique dates, but the number is load-bearing for the chart. I'd suggest either: (a) keep "3" and relabel the column "C/H events" (consistent with chart), or (b) correct to "2 dates" and update the chart. Your call, but (a) is lower-risk.

---

## Sense-Check 5: Manifest Scope — THE SIGNIFICANT ISSUE

**The seven-year quarterly data (`data/seven-year-quarterly.json`) doesn't match the HTML and can't be used to update the charts yet.**

I verified: your generated quarterly arrays sum to 208 total / 47 NP+DI. The HTML arrays sum to 160 total / 30 NP+DI. This is a 30% discrepancy in total and 57% in NP+DI.

The cause is twofold:

1. **Different manifest:** Your source (`seven-year-manifest-events.json`) uses a 54-package manifest (script's 48 + 6 editorial: log4j, xstream, activemq). The HTML was built from the ~60-package hand-curated set (which includes dom4j, spring-messaging, swagger-ui, hazelcast, CXF, MINA, etc. that aren't in your 54). But your 54 also includes activemq which adds events the original didn't have.

2. **Different NP classification in the source data:** The `is_np` and `is_di` flags in `seven-year-manifest-events.json` were set by your session using CWE-only classification, not package+CWE intersection. Line 79 of the quarterly aggregator correctly requires `is_np AND is_di`, but the flags themselves were set wrong in the source dataset. For example, Text4Shell (commons-text, package role=OTHER) has `is_np=true` in your data because CWE-94 is in PARSING_CWES — but commons-text is not a network parser by package role.

**The fix:** The `seven-year-manifest-events.json` needs to be regenerated with package-role-aware NP flags (matching the `build_twelve_month_per_framework.py` approach that uses cached `is_np` from the manifest + NP_OVERRIDES). The quarterly aggregator code itself is fine — the bug is upstream in the event dataset.

**Until this is fixed, don't replace the HTML's hardcoded rmOther/rmNPDI arrays with the generated ones.** The HTML values (160 total, 30 NP+DI) are from our original hand-curated analysis and are closer to correct than the generated 208/47.

**On trimming to strict 48:** Steve mentioned the manifest is 48 from a real portfolio (CVSS 9+ criterion) plus ~12 editorial additions. The right call is probably: keep the 48 as the canonical base, mark the editorial additions clearly, and decide later whether to include them. Don't trim yet — but don't expand the editorial set without Steve's input either.

---

## Sense-Check 6: Anything Else Missed

### DI CWE set includes CWE-434

I noticed the twelve-month generator's DI CWE list includes CWE-434 (file upload). That wasn't in our original DI set — it was flagged as an "open question" in the reconciliation answers. If CWE-434 is now in the DI set, the periodicity numbers would change (file upload events become NP+DI triggers). This should be a deliberate decision, not an accidental inclusion. Check whether CWE-434 was intentionally added or inherited from a broader CWE list.

### The "other" bucket in cwe-families.json shifted significantly

Old DATA blob had `other: 566`. New generator produces `other: 516`. That's 50 entries that moved into named families. The total also grew (1,560 → 1,579 = +19 new KEV entries). The net shift (memory_corruption went from 298 to 342, injection 235→252, etc.) suggests the classifier evolved or the KEV entries themselves have been updated with better CWE tags. This is fine — the generated values are more current — but the shift should be noted when the DATA blob is updated so reviewers don't think it's a bug.

### No generator for http_data or layer_data

The `DATA.http_data` (HTTP-parsing vs non-parsing rates) and `DATA.layer_data` (per-layer KEV/NVD rates) are still not backed by generators. These are the core thesis charts. The `kev-classifier.py` + `kev-layer-classifications.json` from the earlier session provides the raw data, but there's no script that aggregates it into the DATA blob format. This is the natural next step after the current generators stabilize.

### Scratch pages still unvalidated

The 97 ❌ items being "mostly scratch pages" is fine for now — those pages are explicitly labeled as scratch analysis, not published claims. I wouldn't flip priority on any of them. The published pages (dashboard, walkthrough, periodicity) are what matter, and those are now well-covered.

---

## Summary

| Item | Verdict | Action |
|---|---|---|
| Cryptography NP | Confirmed, rule is correct | Audit remaining manifests for similar cases (bouncycastle, jsonwebtoken) |
| TTE methodology | Use regenerated values (CVE-pub-year grouping) | Note methodology change; keep 2025/2026 excluded |
| DATA blob freshness | 23-hour lag is fine | No change needed |
| Netty manifest | Lock 3 events → 1 NP+DI | Consider relabeling "dates" → "events" in summary table |
| **Seven-year quarterly** | **Generated data doesn't match HTML — don't use yet** | **Regenerate source with package-role-aware NP flags** |
| CWE-434 in DI set | Check if intentional | Flag for steve if accidental |
| CWE family shifts | Expected, note when updating | Document in commit message |
| http_data / layer_data generators | Missing | Natural next step |

The twelve-month work is solid and ready to lock in. The seven-year quarterly needs the upstream dataset fix before the generated arrays can replace the HTML. Everything else is clean.

— Claude (original session)
