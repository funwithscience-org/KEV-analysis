# Integrated periodicity page — methodology audit trail

This document captures the model-naming evolution and analytical choices baked into `docs/scratch-integrated.html` so the page itself can stay clean for new readers while keeping the reasoning auditable.

## Model naming evolution

### Tier 1/2/3 → Cat 1/2/3

The original published periodicity page used a "three-tier patching model":

- **Tier 1 — Emergency** (NP+DI app-layer trigger): rebuild now
- **Tier 2 — Regular cadence** (monthly container refresh): blast radius control
- **Tier 3 — Ride the release cycle**: everything else, swept up by the next planned release

The integrated page replaces this with the **Cat 1 / Cat 2 / Cat 3 estate-maturity** framing from `docs/build-mechanics.html#categories`:

- **Cat 1** — apps that absorb a security patch in hours via routine BAU rebuild
- **Cat 2** — apps on a regular cadence (weekly to monthly), where discriminator-driven floor sweeps land cleanly
- **Cat 3** — apps with a long, unscheduled, or governance-blocked rebuild path

**Why the swap.** The Tier framing sorted by *what kind of trigger fires* (emergency vs cadence vs ride). The Cat framing sorts by *what the team can actually do operationally* (fastest credible rebuild SLA). The Cat framing is more accurate because:

1. The discriminator's value depends on which category an app sits in — a Cat 1 estate barely needs a discriminator (everything absorbed in BAU); a Cat 3 estate needs it most (every false-positive emergency is weeks of project work).
2. The "Tier 2 monthly cadence" assumes a team can adopt a monthly cadence, which assumes they're already at Cat 2. Teams in Cat 3 can't credibly run monthly because the cadence collides with the next emergency.
3. The Cat framing makes the second-order benefit explicit — getting churn under control is what enables a team to climb from Cat 3 to Cat 2.

### "30-day release cycle" → "team's normal update process"

The published periodicity page used "rides the normal 30-day release cycle" as a generic description for non-emergency triage. The integrated page replaces this with "the team's normal update process" because the cadence varies by Cat:

- Cat 1: BAU rebuild, hours
- Cat 2: regular cadence, weekly to monthly
- Cat 3: reactive, when something forces an update

The discriminator's job is to keep events out of Cat 1 (Tier 1 in the old framing), not to dictate which downstream cadence they land in.

### "Recall" → "Effectiveness" / "Coverage"

ML-jargon "recall" reads poorly for "the strategy caught the exploited bug." Renamed:

- Table column "Recall" → "Effectiveness"
- "Per-exploit overhead" → "Efficiency (overhead per exploit)"
- "Effective recall" (floor-sweep extended) → "Effectiveness" or "Effective coverage"

The methodology paragraph at the bottom of the integrated page spells out: **effectiveness** = rate of exploited events caught; **efficiency** = patch-event-to-exploit overhead ratio. **Coverage** is used as the neutral measure-of-reach term where appropriate ("85% effective coverage once floor-sweep rescues are counted").

### Star markers visibility

Time-series chart star markers on the 7-year backtest originally used `pointBorderColor: '#fff'` (white border) — readable on dark theme but invisible on the integrated page's light theme. Changed to `pointBorderColor: '#7f1d1d'` (dark red, matched to fill colour family).

## Hacker round provenance

The integrated page's hacker S+A column draws from five rounds of the hacker discriminator across different inputs. All inputs are blinded — the operator does not see KEV/MSF/EDB outcomes during ranking.

| Round | Input | Rationale |
|---|---|---|
| R3 | 175-event Java/Spring blinded set (2018–2026) | Spring 12-month manifest is a subset; production manifest 7-year backtest events are largely covered |
| R4 | 181-event Django/Python blinded set (2009–2026) | Django 12-month manifest is a subset |
| R5 | Same 175-event Java/Spring set + WAF axis | Adds WAF-defensibility (FRIENDLY/MEDIUM/HOSTILE) to each event; minor tier shifts on a few events; cluster verdicts mostly stable |
| R6 | 23-event Node + Netty 12-month blinded set | No prior coverage — needed fresh ranking |
| R7 | 3-event pre-2018 backfill (2013-7285, 2017-12615, 2017-12617) | These 3 exploited events on the production manifest were outside R3's 2018+ window; backfilled so the per-event detail table doesn't show "n/a" |
| R8 | 69-event OS-container Amazon Linux 2023 blinded set | Surfaces NVD keyword noise (~50 of 69 events are downstream apps, not OS components); reproduces NP+DI = 0 result on cleaned set |

All blinded inputs are stored in `data/_hacker-input-blind-v*.json`. All ranking outputs are in `analyst-reports/2026-04-{25,26}-hacker-ranking-v*.md`. The structured per-CVE tier judgments are aggregated in `data/hacker-tiers.json`.

## What's reproducible vs. what isn't

### Reproducible from script

- `data/twelve-month-per-framework.json` — produced by `scripts/build_twelve_month_per_framework.py`. Tested by `tests/test_twelve_month_per_framework.py`.
- `data/seven-year-quarterly.json`, `data/seven-year-npdi-events.json`, `data/seven-year-per-framework.json`, `data/seven-year-manifest-events.json` — `scripts/build_seven_year_*.py`. Tested by `tests/test_seven_year_npdi.py`.
- `data/hacker-tiers.json`, `data/waf-defensibility.json`, `data/integrated-page-aggregates.json` — `scripts/build_hacker_tier_data.py`. **Source of truth: the analyst-report markdown files.** Re-running the script after editing tier judgments in the analyst reports re-derives these JSONs.
- `data/kev-layer-classifications.json` — `data/kev-classifier.py`. Tested by `tests/test_classifications.py`.

### Manually curated (not reproducible from raw data)

- **Hacker tier judgments themselves** — the analyst reports are the operator's blinded reasoning. Not algorithmically derivable. Stored as text + summarized in `data/hacker-tiers.json`.
- **WAF-defensibility tags** — operator judgment from R5; stored in `data/waf-defensibility.json`.
- **AI-rescue event identification** — operator-curated list of which events the AI scan would have promoted from "Other" to "AI rescue" (sequelize SQLi, lodash _.template, spring-boot actuator, ASGI header spoof, Ghostcat, Tomcat partial-PUT, ActiveMQ Jolokia). Encoded in `scripts/build_hacker_tier_data.py` and tested implicitly by the per-month aggregates.

### Hardcoded in HTML, derived from the JSON

The integrated page's chart datasets and table values are currently hardcoded copies of `data/integrated-page-aggregates.json`. Future cleanup: have the page load `integrated-page-aggregates.json` and render charts/tables from it directly, eliminating the duplicate-source-of-truth problem (this is an open refactor item — flagged in the data-freak review punch list).

## Data files inventory (post-2026-04-26)

```
data/
├── CLASSIFIER.md                                    KEV-layer classifier methodology
├── INTEGRATED-PAGE-AUDIT-TRAIL.md                   ← this file
├── hacker-tiers.json                                NEW: per-CVE hacker tier judgments
├── waf-defensibility.json                           NEW: WAF status per exploited event
├── integrated-page-aggregates.json                  NEW: per-month, per-quarter, per-year strategy counts
├── twelve-month-per-framework.json                  Reproducible
├── seven-year-{npdi-events,quarterly,per-framework,manifest-events}.json  Reproducible
├── kev-{classifier.py,layer-classifications.json,snapshot-2026-04-26.json}  Reproducible
├── di-reclassification.json, di-cwe-backtest.json   Methodology
├── doc-canonical-npdi-events.json                   Methodology
├── _hacker-input-blind-v{2,3,4,6,8}.json            Blinded inputs (raw)
├── _kev-publication-dates.json                      Raw cache (KEV)
├── _metasploit-cves.json, _exploitdb-cves.json      Raw caches
├── _manifest-osv-cache.json, _netty-osv-cache.json  Raw caches (OSV)
├── _nvd-cwe-434-cache.json                          Raw cache (NVD)
├── _osv-alias-cache.json                            Raw cache
├── _seven-year-frameworks-cache.json                Raw cache
├── _cwe-434-backtest.json                           Raw analysis
├── cwe-families.json, top-products.json, tte.json   Derived
└── analyst-reports/                                 Hacker round reports + reviews
```

## Open items (for next session)

- **Move chart data to load from `integrated-page-aggregates.json`** instead of hardcoded JS arrays. Eliminates the dual-source-of-truth between the page and the JSON.
- **Add a test** that checks the integrated-page-aggregates totals match the derived numbers (e.g., sum of `seven_year_per_year[*].all_ch` == 223).
- **Decide whether to replace the published `periodicity.html`** with this integrated page. If yes: drop `noindex`, swap canonical URL, update sitemap, redirect old anchors.
