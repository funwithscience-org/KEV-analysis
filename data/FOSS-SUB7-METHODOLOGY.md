# FOSS sub-7 server-side exploited CVEs — methodology & repro

A repeatable pipeline for assembling and scoring the set of FOSS, server-side
library CVEs with CVSS v3 < 7.0 that have exploitation evidence. The result
is used to test whether our threat-prioritization model (built on Crit/High
historicals) generalizes down to the medium severity band.

Generated: 2026-04-29.

## Question being answered

Triaging the full Critical+High+Medium NVD volume is operationally impractical
(~55k CVEs/year). Our model uses Crit+High as the workable band. **Does that
choice cost us coverage of mediums that actually get exploited, or does the
NP+DI+DQ / Hacker filter still catch them when applied to the same packages?**

## Scope

- **FOSS only.** Sourced via OSV.dev's per-ecosystem bulk feeds.
- **Server-side only.** Client-side libs (browser DOM frameworks, desktop
  document parsers, mobile SDKs) are excluded by an explicit deny list.
- **CVSS v3 < 7.0.** Strict less-than. CVSS v4 used as fallback when v3 absent.
- **Exploitation evidence required.** CVE must appear in CISA KEV,
  Metasploit modules, or ExploitDB (filtered: type ≠ dos, description ≠
  "Proof of Concept" / "PoC").

## Data sources

| Source | Endpoint | Notes |
| --- | --- | --- |
| OSV.dev bulk | `https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip` | One zip per ecosystem. Maven, npm, PyPI, Go, RubyGems, crates.io, Packagist, NuGet, Hex. |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Pull date 2026-04-29, catalogVersion 2026.04.28, 1,585 entries. |
| Metasploit | `modules_metadata_base.json` from rapid7/metasploit-framework master | 6,619 module-CVE references, 3,109 distinct CVEs. |
| ExploitDB | `files_exploits.csv` from gitlab.com/exploit-database/exploitdb | ~46,993 rows, 24,941 distinct CVEs. After type/PoC filter: 124 CVEs intersect our universe. |

## Pipeline (4 stages)

All scripts live in `scripts/foss_sub7_*.py` and write to
`data/_foss-sub7-cache/` for intermediates, then to canonical `data/*.json`
files for outputs.

```
scripts/foss_sub7_scan_osv.py            # 1. Pull + parse OSV bulk feeds → osv_parsed/{ECO}.json
scripts/foss_sub7_server_side_filter.py  # 2. Apply server-side judgment filter
scripts/foss_sub7_build_dataset.py       # 3. Join exploit evidence + write data/foss-sub7-exploited.json + report
scripts/foss_sub7_score.py               # 4. Score against NP+DI+DQ + Hacker → data/foss-sub7-scoring.json
```

The first three stages produce the **dataset**. The fourth stage produces the
**scoring**. The dataset and the scoring are stored separately so the data
guy can re-score with a tweaked NP/DI rule without re-pulling OSV (~30
minutes + several GB of disk).

### Repro from a clean checkout

```bash
pip install --break-system-packages cvss requests
python3 scripts/foss_sub7_scan_osv.py        # ~30 min, network-bound; writes osv_parsed/
# (download + parse the exploit catalogs — ad hoc; see "exploit catalog
# acquisition" below for the canonical sources. Cached in data/_metasploit-cves.json
# and data/_exploitdb-cves.json already.)
python3 scripts/foss_sub7_server_side_filter.py
python3 scripts/foss_sub7_build_dataset.py   # writes data/foss-sub7-exploited.json
python3 scripts/foss_sub7_score.py           # writes data/foss-sub7-scoring.json
tests/run.sh
```

The deduplicated CVE-level input to the scoring stage
(`data/foss-sub7-unique.json`) is committed for reproducibility — running
`foss_sub7_score.py` against it reproduces the headline numbers exactly.

## Filters

### OSV-side

- `severity[]` must contain a `CVSS_V3.x` entry with a parseable vector.
  CVSS v4 is accepted as fallback if v3 is absent.
- Computed base score must be strictly < 7.0 and > 0.
- Aliases must contain at least one CVE-YYYY-NNNNN+ ID.
- `withdrawn != null` records were not explicitly filtered; none survived.

### Exploitation evidence

A CVE counts as exploited if **any** of:
- KEV listing.
- Metasploit module reference.
- ExploitDB entry where `type ∈ {remote, webapps, local, shellcode}` AND
  description does not match `/proof[ -]?of[ -]?concept|PoC/i`.

This filter excludes 3,806 ExploitDB DoS-only and 19 PoC-only entries.

### Server-side judgment

Hardcoded deny list of client-side packages in
`scripts/foss_sub7_server_side_filter.py`:

| Package family | Reason | CVEs excluded |
| --- | --- | --- |
| jQuery (all repackages) | Browser DOM library; XSS executes client-side | 5 |
| Joplin | Electron desktop app | 2 |
| Puppeteer | Underlying CVE is Chromium V8 UAF | 1 |
| CefSharp.* | Chromium embedded into .NET desktop | 1 |
| docsify | Static-site generator that runs in user's browser | 1 |
| **Total excluded** | | **10** |

Everything else defaults to server-side. The judgment-call cases
(BouncyCastle, lxml, mobiledetectlib, pip, Vite) are explicitly noted in
the analyst report's uncertainty section. Reclassifying any of them
client-side drops the count by 1–4.

## Scoring

The `foss_sub7_score.py` script applies the formalized model rules from
`/mnt/.claude/CLAUDE.md` (sections "NP Classification Rule" 2026-04-25 and
"Widened DI Definition" 2026-04-23).

### NP (Network Parser)

Per-package boolean. NP=true if the package's primary purpose is processing
untrusted network input OR driving security decisions from untrusted input.
The classifier uses a hardcoded per-package map (98 distinct packages in
this dataset). Conservative NP-not-true cases (1 / 98 = 1%): `slo-generator`
(SLO budget calculator from yaml — server-side but not parsing untrusted
network input).

### DI (Dangerous Input)

Per-CVE boolean. DI=true if the CVE's CWE family is in the formal DI set:
- Injection: CWE-77, -78, -79, -89, -90, -91, -93, -94, -95, -96, -97, -113, -116, -917
- Deserialization: CWE-502
- Path traversal: CWE-22, -23, -35, -73
- SSRF: CWE-918
- XXE: CWE-611
- HTTP smuggling: CWE-444
- HTTP request handling: CWE-74
- Auth bypass via input manipulation (widened set): CWE-287, -289, -306, -345, -693, -863, -1321
- Other widened: CWE-776

CWE inference here is regex-on-summary-text, not OSV `database_specific.cwe_ids`
lookup. The honest concern (top-3 in the analyst report): ~5 entries had
ambiguous primitive kinds where text inference might disagree with NVD's
formal CWE assignment. Spot-check before any high-stakes decision.

### DQ (Data Quality / AI rescue)

If NP=true and DI=false, the entry is re-evaluated against summary text for
DI behavior. If the bug behaves like DI even when the CWE label says
otherwise (common rescues: missing CWE, generic CWE-20, generic CWE-200),
DQ=true.

### Hacker tier (S/A/B/C/D)

Three independent axes scored per CVE event:
- **default_config** — works against the default/typical install
- **network_edge** — reachable from the public network without prior foothold
- **primitive_direct** — yields RCE / auth-bypass / mass-data-exfil directly
- co-tag **auth_missing** — no credentials needed

Tier mapping:
- S = all three axes + auth_missing
- A = two axes + auth_missing, OR all three with auth required
- B = one axis + auth_missing, OR two axes with auth required
- C = one axis with auth required
- D = DoS-only, dev-environment-only, or otherwise impractical at scale

A heuristic cap is applied: XSS / CSRF / open-redirect mechanically scored
A get downgraded to B because they don't survive a 30-second hacker-bench
"would I deploy this day-1?" test. This is the largest single sensitivity
in the result; the analyst report quantifies it (without the cap, Hacker
S+A jumps from 26% to ~60%).

## Headline result (n=135 distinct CVEs)

| Filter | Caught | Pct |
| --- | --- | --- |
| NP+DI raw | 111 | 82.2% |
| NP+DI+DQ | 116 | 85.9% |
| Hacker S+A | 35 | 25.9% |
| **Union** | **118** | **87.4%** |
| Intersection | 33 | 24.4% |

By evidence source (the strongest signal first):

| Source | n | Union catch | Notes |
| --- | --- | --- | --- |
| KEV | 4 | 50% (2/4) | Two misses: HTTP/2 Rapid Reset DoS (D-tier), Craft CMS chained session storage |
| Metasploit | 18 | 94% | Strong NP+DI catch + Hacker overlap |
| ExploitDB | 124 | 88% | Demonstrated-exploitable, not necessarily ITW |

By ecosystem: see `aggregate.by_ecosystem` in `data/foss-sub7-scoring.json`.

## Output files

| Path | What | Lifetime |
| --- | --- | --- |
| `data/foss-sub7-exploited.json` | 156 per-package records (raw dataset) | Canonical |
| `data/foss-sub7-unique.json` | 135 distinct-CVE records (input to scorer) | Canonical |
| `data/foss-sub7-scoring.json` | 135 records + aggregate metadata | Canonical |
| `data/_foss-sub7-cache/*` | OSV zip cache, parsed-per-eco JSON, intermediates | Local; not committed |
| `analyst-reports/2026-04-29-foss-sub7-exploit-scan.md` | Pipeline result narrative | Pinned |
| `analyst-reports/2026-04-29-foss-sub7-model-backtest.md` | Model scoring narrative | Pinned |
| `tests/test_foss_sub7_scoring.py` | Pins headline numbers, drift catcher | Pinned |

## What this answers and what it doesn't

**Answers.** Whether the structure test (NP+DI+DQ) and the attacker test
(Hacker S+A) generalize from the Crit/High band where they were calibrated
down to the medium band where we don't routinely triage. On this evidence
they do — the structure test catches 86% of medium exploitation for free,
and the union catches 87%.

**Doesn't answer.**
1. **In-the-wild prevalence at sub-7 severity.** ExploitDB-strong evidence is
   "demonstrated exploitable" not "exploited at scale". The 4 KEV-cleared
   CVEs are the only ones at the higher prevalence threshold.
2. **Whether NP+DI is doing real work or just package-membership coloring.**
   97 of 98 distinct packages classify NP. On this dataset NP+DI essentially
   collapses to "does the bug have an injection-class CWE." The discriminator
   is doing weaker work than at C/H.
3. **Lows (CVSS < 4.0).** Out of scope; OSV CVSS gating excludes ~30-40% of
   entries that lack a parseable v3 score, and CVSS v4 fallback was rare.
4. **Linux distro / OS-layer / non-language packaging.** OSV doesn't aggregate
   distro packages. Apache httpd, system OpenSSL, BIND, etc. are absent.

## Audit trail

Most-recent OSV pull: 2026-04-29. Most-recent KEV snapshot referenced by
the score script: catalogVersion 2026.04.28 (1,585 entries). To re-score
against a fresher KEV catalog, re-run the pipeline from
`scripts/foss_sub7_scan_osv.py`.

Drift detection: `tests/test_foss_sub7_scoring.py` pins record counts,
aggregate percentages within tolerance, and the 4 KEV-confirmed CVE IDs.
If the OSV / KEV / MSF / EDB upstream data shifts in a way that changes
these, the test fails loud and the data guy investigates.
