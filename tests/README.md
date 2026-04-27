# Numeric regression tests

Fail-loud suite guarding every derived number on the published pages.

## Run

```
tests/run.sh            # fast — canonical classifier cases + DATA invariants
tests/run.sh --full     # also re-classify the pinned snapshot end-to-end (~1579 entries)
```

Zero dependencies beyond Python 3.9+ standard library. Each test script is
standalone and can be run individually:

```
python3 tests/test_kev_classifier.py
python3 tests/test_kev_classifier.py --full
python3 tests/test_data_invariants.py
python3 tests/test_http_data.py
python3 tests/test_classifications.py
```

Exit 0 on pass, 1 on any failure. All failures are printed before exit so you
see every problem, not just the first one.

## What's covered

| Script | Protects |
|---|---|
| `test_kev_classifier.py` | Layer assignment for 69 canonical edge cases (Cisco Webex → JVM not VPN, Apple Safari → browser not OS, Adobe ColdFusion → JVM not productivity, Qualcomm chipset → firmware, etc.). `--full` additionally re-runs the classifier over the pinned snapshot and verifies 1,579/1,579 entries match the stored classification — catches silent rule-order drift. |
| `test_data_invariants.py` | DATA blob in each published HTML page: sums match classifications JSON, every rate equals `round(kev/nvd*100, 2)`, no rate > 100%, all 15 layers present, dashboard ≡ index. |
| `test_http_data.py` | `http_data` lift table: counts bounded by totals, rates arithmetically correct, lift ≈ `http_rate/nonhttp_rate`, dashboard ≡ index. |
| `test_classifications.py` | `data/kev-layer-classifications.json` integrity: required fields, year matches CVE ID, layer in canonical set, summary counts recomputable from entries, snapshot count matches. |
| `test_cve_reference.py` | `data/cve-reference.json` and `docs/cve-reference.html` are in sync, every source artifact's CVEs roll into the union, canonical anchors (Log4Shell, Spring4Shell, Tomcat-PUT pair, Ivanti EPMM, Ghostcat) are present, no duplicates, hacker tier and combined verdict values are in the canonical set. |

## Workflow rule

**Before editing any published page (`docs/*.html`, DATA blob, layer counts, rates):**

1. Pull latest (`git pull origin main`).
2. Make the edit.
3. Run `tests/run.sh`.
4. Fix anything red before committing.

**When adding a new numeric claim to a published page,** add a test that proves
it. Copy-paste a similar check from the existing suite and narrow it to the new
number. Claims without tests rot.

**When fixing a failing test:**

- Re-read the check. If the new number is intentional, the old expectation was
  wrong — update the expectation and say why in the commit.
- If the new number is unintentional, the edit broke something — fix the edit,
  not the test.
- "Relax the tolerance" is almost never the right move. The tolerances in
  `test_http_data.py` are already the sloppiest that still catch drift.

## Adding new pages to the suite

If a new HTML page gets its own `const DATA = {...};` line, add it to
`DATA_BLOB_SOURCES` in `_common.py`. The invariant and http tests will pick
it up automatically and enforce cross-page identity.

## What this suite does NOT catch

- Prose consistency (e.g. "the dashboard says OS 78%, the walkthrough says OS
  80%"). Deliberately out of scope — prose tests rot on every copy-edit.
  Fix prose drift by editing; the DATA blob is the canonical source, the
  prose should follow it.
- Whether the *underlying* NVD denominator is stale. The suite enforces rate
  math given the denominator; it cannot re-derive the denominator. See
  `data/CLASSIFIER.md` for the known caveat.
- Statistical claims about periodicity / backtest reductions. The underlying
  datasets are still being versioned (DI CWE set expansion), so pinning
  expectations would create churn.
