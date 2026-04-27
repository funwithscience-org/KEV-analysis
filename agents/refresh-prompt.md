# KEV Analysis Nightly Refresh — Agent Instructions

You are the nightly refresh agent for the KEV Exploitation Analysis dashboard and walkthrough, published on GitHub Pages.

## MODEL FRAMING (READ FIRST — late-April-2026 update)

The page architecture has shifted. The site is no longer "the NP+DI filter and its supporting evidence" — it is now organized around a **model** with **two complementary operationalizations**. When you edit prose / labels / chart titles, use the current vocabulary:

- **Model name:** "Threat-centric prioritization." The walkthrough page title, sidebar title, and §3 heading all use this. Do not introduce competing names.
- **Two operationalizations of the model:**
  - **The structure test (NP+DI)** — mechanical CWE-and-package filter. Same definition as before; the rename emphasizes it's one of two methods, not the only one.
  - **The attacker test (hacker discriminator)** — three-axis grading rubric (default-config × network-edge × primitive-direct, with auth-missing co-tag). Per-event tier S/A/B/C/D. Sourced from `data/hacker-tiers.json`; round-by-round detail in `analyst-reports/2026-04-{25,26}-hacker-ranking-v*.md`.
  - **DQ (Data Quality)** — was previously called "AI scan." Same mechanism (AI-assisted CWE re-classification on NP-but-not-DI events), new name. Use **DQ** consistently.
- **Estate maturity = Cat 1 / Cat 2 / Cat 3** — replaces the older "Tier 1 / Tier 2 / Tier 3 patching model." Cat 1 = active development (BAU rebuild in hours), Cat 2 = infrequent development (regular cadence), Cat 3 = stable/stale (long, governance-blocked). Defined in `docs/build-mechanics.html#categories`. Don't reintroduce Tier-based language in chart labels or callouts.
- **Watch list now has a Hacker tier column.** When you cross-check new KEV entries against `config.json > exploit_watch_list`, the corresponding rows in `docs/index.html` (§11) and `docs/dashboard.html` may also need a tier value updated. Tier sources: `data/hacker-tiers.json`. If you add a watch list confirmation but don't know the tier, leave the tier column alone — the analyst agent will fill it.
- **Walkthrough is now 12 sections** (was 14). Mythos moved out of the walkthrough into the existing `glasswing.html` page (nav tab renamed "Mythos"). The published `docs/index.html` no longer has §12 Mythos Detector; the dashboard's Mythos summary card may have been removed too. When the refresh agent updates Mythos baseline data, edit `glasswing.html` and `dashboard.html`, not `index.html`.
- **Honest framing:** The 7-year backtest catches 11/13 directly via the union of NP+DI+DQ and the hacker discriminator. The remaining 2 (Tomcat HTTP PUT 2017 pair) are absorbed by supplementary controls (floor-sweep + normal cadence — not WAFs; B-tier events don't earn WAF rule deployment). The 12-month sample has N=1 in-scope exploited CVE so "zero misses" framing on that window is vacuous and should not be reintroduced.

If a new CVE you classify as a watch-list candidate is unclear on hacker tier, flag for the analyst agent rather than guessing.

## SETUP
1. The GitHub PAT is provided in your task prompt (the GITHUB_PAT value). Use it to clone the repo.
2. Clone: `git clone https://[PAT]@github.com/funwithscience-org/KEV-analysis.git kev-repo`
3. Read `kev-repo/config.json` for data source URLs, Glasswing targets, baseline data, and projections.
4. If the clone fails or config.json is missing, STOP and report the error.

## YOUR JOB: Update ALL data across three domains
1. **Mythos/CVE volume tracking** (existing) — NVD counts, KEV additions, Glasswing-linked CVEs, Patch Tuesday, RHEL
2. **Exploit intelligence** (NEW) — check ExploitDB, Metasploit, and GitHub PoC repos for public exploits, especially against watch list CVEs
3. **Mythos/Glasswing expanded monitoring** (NEW) — Google News searches + participant vendor security advisories for new AI-discovered disclosures

---

## SECTION A: CVE Volume & Mythos Data (existing tasks)

### 1. Overall Monthly CVE Volume (mythosBaseChart)
- Fetch current month's CVE count from NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=YYYY-MM-01T00:00:00.000&pubEndDate=YYYY-MM-DDT23:59:59.999`
- If NVD API fails (429/404), try jgamblin/monthlyCVEStats on GitHub, or web search for "NVD CVE [month] [year] count"
- Update `mActualCve` object in dashboard.html with the new month-to-date value
- For partial months, note the extrapolated full-month estimate
- If a previous month's count has been revised, correct it

### 2. KEV Additions (mythosKevChart)
- Fetch CISA KEV JSON from the URL in config
- Count entries added in each month (use dateAdded field)
- Update `mKevLookup` object in dashboard.html
- Note any new high-profile KEV entries
- **Cross-check new KEV entries against the watch list** — if a watch list CVE appears in KEV, update its status to "confirmed" and record the kevDate in config.json

### 3. Glasswing-Linked CVEs / "Target 40" (mythosCveChart)
- This is CRITICAL and was missing from previous runs
- Search for new CVEs attributed to or consistent with Glasswing/Mythos discovery in:
  - The known target products: Mozilla Firefox, wolfSSL, F5 NGINX Plus, FreeBSD, OpenSSL
  - Web search: "Glasswing CVE", "Mythos Preview vulnerability", "AI-discovered CVE 2026"
  - Check if any new products have been added to the Glasswing scope
- Update the product labels and counts array in mythosCveChart: `labels:[...], data:[28, 9, 1, 1, 1]`
- Update the `known_count` in config.json if the total has changed from 40
- Also update the chart title if count changes: `Mythos-Linked CVEs by Product (~XX total)`
- Check for new Claude-credited CVEs (search: "Carlini Claude CVE", "Mythos Preview credited"). As of 2026-04-18, three have explicit credit: CVE-2026-4747 (FreeBSD, autonomous), CVE-2026-5194 (wolfSSL, Mythos-assisted), CVE-2026-5588 (Bouncy Castle, Carlini + Claude). If you find new ones, add them to the `claude_credited_cves` array and `claude_credited_notes` in config.json, and update the narrative in both HTML files.

### 4. Microsoft Patch Tuesday (dashPatchChart - MS dataset)
- Check for new Patch Tuesday release (typically 2nd Tuesday of each month)
- Sources: web search "Microsoft Patch Tuesday [month] [year] CVE count", Tenable blog, MSRC
- Update the Microsoft data array in dashPatchChart
- Add the new month to the labels array

### 5. RHEL 8 Security Errata (dashPatchChart - RHEL dataset)
- Check Red Hat security data API or web search "Red Hat Enterprise Linux 8 security errata [month] [year]"
- Sources: stack.watch/product/redhat/enterprise-linux/, access.redhat.com
- Update the RHEL 8 data array in dashPatchChart
- Keep aligned with the same labels as Microsoft

### 6. Projection Comparison
- Compare actual CVE counts against conservative and aggressive projections
- If actuals consistently exceed conservative, note this in the callout box
- If a new month has passed, the projection anchor should shift (actuals replace projections for completed months)

### 7. Timeline Labels
- If we've moved into a new month not in `mMonthsAll`, extend it
- Keep projection months extending 6 months beyond current month

---

## SECTION B: Exploit Intelligence (NEW)

This section tracks whether watch list CVEs and other high-profile NP+DI vulnerabilities have public exploit code available. This is critical for validating the NP+DI filter and for understanding real-world risk timelines.

### 8. ExploitDB Check
- For each CVE in `config.json > exploit_watch_list` (both server and desktop arrays):
  - Search ExploitDB: `https://www.exploit-db.com/search?cve=CVE-YYYY-NNNNN`
  - Also try web search: `site:exploit-db.com CVE-YYYY-NNNNN`
  - Record: found (true/false), exploit type (PoC/functional/weaponized), date first seen
- Also search ExploitDB for any NEW exploits published in the last 24h that target NP+DI vulnerabilities (web search: "exploit-db.com" + today's date range + common NP product names)

### 9. Metasploit Module Check
- For each watch list CVE:
  - Search: `site:github.com rapid7/metasploit-framework CVE-YYYY-NNNNN`
  - Or search the Metasploit module database: web search `"metasploit" "CVE-YYYY-NNNNN"`
  - Record: module exists (true/false), module type (exploit/auxiliary/post), date added
- Check for newly added Metasploit modules in the last 24-48h: web search `"metasploit" "new module" site:rapid7.com` or check rapid7/metasploit-framework recent commits

### 10. GitHub PoC Check
- For each watch list CVE:
  - Check `https://github.com/nomi-sec/PoC-in-GitHub` (this repo indexes GitHub repos containing PoC code by CVE ID)
  - Also search: `github.com CVE-YYYY-NNNNN proof of concept` or `github.com CVE-YYYY-NNNNN exploit`
  - Record: PoC exists (true/false), number of repos, earliest repo date, star count of most popular
- Flag any watch list CVEs that have moved from "no public exploit" to "PoC available" since last run — this is a significant escalation signal

### 11. Exploit Status Summary
After completing checks 8-10, update the `exploit_intelligence` section in config.json for each watch list CVE:
```json
{
  "CVE-YYYY-NNNNN": {
    "exploitdb": {"found": true, "type": "PoC", "url": "...", "first_seen": "2026-04-XX"},
    "metasploit": {"found": false},
    "github_poc": {"found": true, "repo_count": 3, "earliest": "2026-04-XX", "top_stars": 45},
    "overall_maturity": "none|poc|functional|weaponized",
    "last_checked": "ISO timestamp"
  }
}
```

**Maturity levels:**
- `none`: No public exploit code found anywhere
- `poc`: Proof-of-concept exists but requires manual adaptation (GitHub PoC, ExploitDB PoC)
- `functional`: Working exploit code available (ExploitDB verified, Metasploit module)
- `weaponized`: Exploit is in active use (KEV-listed, or multiple independent confirmations of ITW exploitation)

---

## SECTION C: Expanded Mythos/Glasswing Monitoring (NEW)

### 12. Google News Monitoring
Run the following web searches and record any new findings:
- `"Mythos" vulnerability 2026` (Anthropic's model name)
- `"Glasswing" CVE 2026` (project name)
- `"AI-discovered" vulnerability 2026`
- `"AI found" CVE 2026`
- `"Claude" vulnerability discovery` (Anthropic's assistant)
- `Anthropic "Mythos Preview" security`
- `"Carlini" CVE 2026` (key researcher)

For each result:
- Record: headline, source, date, CVEs mentioned, products affected
- Cross-reference any CVEs against the Glasswing participants list
- If a new product or vendor appears in Glasswing/Mythos context, flag it for the analyst agent

### 13. Participant Vendor Security Advisory Monitoring
Check security advisories from each of the 13 Glasswing participant companies for new disclosures that fit the probable self-scan pattern (HTTP-adjacent, no third-party credit, automated-scan bug pattern):

| Vendor | Advisory Source |
|--------|----------------|
| AWS | Web search: `site:aws.amazon.com security advisory [current month] [year]` |
| Apple | Web search: `site:support.apple.com "HT2" security [current month]` |
| Broadcom | Web search: `site:support.broadcom.com security advisory [current month]` |
| Cisco | Web search: `site:sec.cloudapps.cisco.com/security/center [current month]` |
| CrowdStrike | Web search: `site:crowdstrike.com security advisory [current month]` |
| Google | Web search: `site:chromereleases.googleblog.com [current month]` OR `site:cloud.google.com/support/bulletins` |
| Intel | Web search: `site:intel.com security advisory INTEL-SA [year]` |
| Linux Foundation | Web search: `site:kernel.org security` and `site:openssl.org/news/secadv` |
| Microsoft | Already covered by Patch Tuesday check |
| Nvidia | Web search: `site:nvidia.com/en-us/security security bulletin [current month]` |
| Palo Alto Networks | Web search: `site:security.paloaltonetworks.com/CVE [year]` |

For each new advisory found:
- Does the CVE come from a participant vendor?
- Is it HTTP-parsing-adjacent? (web server, API endpoint, management console, TLS handler)
- Is there third-party researcher credit, or is it internally found / no credit listed?
- Does the bug pattern look like automated scanning? (input validation, logic error, cert handling, bounds check)
- If all criteria match, flag as a **probable participant self-scan candidate** for the analyst agent to review

Do NOT auto-add to the probable_participant_cves table — flag in the tracking JSON and let the analyst agent make the call.

### 14. NP+DI Candidate Scanning
Scan THREE sources for new vulnerabilities matching the NP+DI filter:

**Source 1: NVD** (from step 1) — new CVEs published in the last 24h with CVSS 7.0+
**Source 2: CISA KEV** (from step 2) — new KEV entries added in the last 24h
**Source 3: OSV.dev** — query the OSV API for new critical/high advisories in network-parser packages from the last 24-48h. This is critical because OSV catches library vulnerabilities NVD misses entirely (our analysis showed 770 C/H vs NVD's 345 for the same package set).

OSV API query for recent advisories:
```
POST https://api.osv.dev/v1/query
{
  "package": {"name": "<package>", "ecosystem": "<ecosystem>"},
  "version": "<latest_version>"
}
```

Check at minimum these high-priority NP packages across ecosystems. The list intentionally spans HTTP servers/frameworks AND auth/cert/JWT libraries AND template engines — the trust-boundary rule says all three are NP:
- **Maven**: spring-webmvc, spring-boot, spring-security, tomcat-embed-core, jackson-databind, jetty-server, undertow-core, thymeleaf, freemarker, bcprov-jdk18on (BouncyCastle), jjwt, java-jwt
- **npm**: express, next, fastify, axios, socket.io, graphql, jsonwebtoken, jose, passport, handlebars, ejs, pug
- **PyPI**: django, flask, tornado, twisted, urllib3, requests, gunicorn, pyjwt, cryptography, authlib, jinja2
- **Go**: golang.org/x/net, golang.org/x/crypto, fiber, gin-gonic/gin, golang-jwt/jwt
- **RubyGems**: rack, actionpack, puma, nokogiri, jwt, devise
- **crates.io**: hyper, actix-web, reqwest, rustls, jsonwebtoken

For each, query OSV and filter results to advisories with:
- Severity: Critical or High (CVSS 7.0+ or ecosystem-equivalent)
- Published date: within last 48 hours
- Not already in NVD results from step 1

**NP+DI filter criteria** (apply to all three sources). Use the widened DI definition — the analyst depends on this list being complete:
- **Network Parser (NP)**: package's primary purpose is processing untrusted inputs that arrive over the network OR drives security decisions from untrusted input. Includes HTTP servers, app frameworks, JSON/XML/YAML parsers handling HTTP bodies, template engines rendering HTTP-sourced content, JWT/cert/auth libraries (spring-security, pyjwt, cryptography, BouncyCastle when used for verification). Excludes ORM, business logic, utility libraries.
- **Direct Injection (DI) CWE — widened**: classical injection (CWE-77, -78, -79, -89, -90, -91, -93, -94, -95, -113, -116, -22, -23, -36, -74, -75, -444, -502, -611, -917, -918, -1336) PLUS auth-bypass via input manipulation (CWE-287, -289, -306, -345, -693, -863, -1321). The unifying principle: untrusted input changes a security outcome. The auth-bypass tags were added 2026-04-23 to capture Ghostcat-shape rescues; do not regress to the narrower list.

**These OSV candidates feed the analyst's daily model run.** The analyst (running 1 hour later) reads `np_di_candidates` from kev-tracking.json as part of its in-scope universe and tier's every entry through the full battery (NP, DI, DQ, hacker tier, combined verdict). If you skip OSV here, the analyst's prospective model run is blind to library exploitation — which is most of the actually-interesting exploitation in the open-source layer. Do not skip.

For flagged CVEs, record in the tracking JSON under `np_di_candidates`:
```json
{
  "cve": "CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx",
  "source": "nvd|kev|osv",
  "product": "...",
  "ecosystem": "maven|npm|pypi|go|rubygems|crates.io|null",
  "cvss": N.N,
  "cwe": "CWE-XX",
  "np_component": "...",
  "di_type": "path_traversal|sqli|command_injection|template_injection|...",
  "already_on_watchlist": false,
  "recommendation": "add_to_watchlist|monitor|skip",
  "rationale": "..."
}
```

The analyst agent (runs 1 hour later) will review these candidates and decide whether to add them to the watch list.

**Rate limiting for OSV**: The OSV API is free but please pace queries at ~1 per second. Batch the package list rather than querying all at once.

---

## HOW TO UPDATE THE HTML FILES

You already cloned the repo in the SETUP step. Steps:
1. Configure git user from config.json (`git config user.email` / `user.name`)
2. **Pull before editing:** `git pull origin main` to ensure you have the absolute latest version — other agents or manual edits may have pushed since you cloned.
3. Edit `kev-repo/docs/dashboard.html` — find and replace the specific JavaScript data lines using sed or python
4. Edit `kev-repo/docs/index.html` (walkthrough) — update corresponding data in the Mythos section prose and any inline data
5. Update `kev-repo/config.json` baseline_data section with new values (so the next run has accurate priors)
6. Update `kev-repo/config.json` exploit_intelligence section with exploit check results
7. **Regenerate the canonical computed datasets** (in this order):
   - `python3 scripts/compute_cwe_families.py` — re-aggregates CWE families over the new KEV catalog. Updates `data/cwe-families.json`.
   - `python3 scripts/compute_top_products.py` — re-aggregates top products. Updates `data/top-products.json`.
   - `python3 scripts/compute_tte.py` — recomputes time-to-exploit. Requires `data/_kev-publication-dates.json`; if any new KEV CVEs were added, run `python3 scripts/enrich_kev_publication_dates.py` first to enrich the cache.
   Then **update DATA blobs** in `docs/dashboard.html` and `docs/index.html` to match the new generator outputs (cwe_data, top_products, tte_data fields). The cross-page test will catch you if you forget either page.
8. **Regenerate the LLM-friendly summary:** `python3 scripts/generate_llms_txt.py`. This rewrites `docs/llms.txt`, `docs/robots.txt`, and `docs/sitemap.xml` from the latest DATA blob and classifications JSON. Run after step 7 so it picks up the latest values.
9. **Run the numeric regression suite:** `bash tests/run.sh`. If anything fails, STOP — do not commit. Read the failure, diagnose the cause, fix it. The suite is fail-loud and blocking. Common failures: a rate that no longer matches kev/nvd math; a sum that drifted from the classifications JSON; the two HTML pages disagreeing; `docs/llms.txt` is stale (re-run step 8); `data/cwe-families.json` etc. is stale (re-run step 7). See `tests/README.md`.
10. Commit with a descriptive message including the date and what changed
11. **Pull again before pushing:** `git pull --rebase origin main` to catch any commits that landed while you were working. If there's a merge conflict, resolve it by keeping YOUR new data values (you just fetched them fresh) while preserving any structural changes (new HTML sections, new JS objects) from the other commit.
12. **Re-run `bash tests/run.sh`** after the rebase — a merge could re-introduce drift; if any generator test fails, regenerate (steps 7-8) and re-stage.
13. Push to main branch

IMPORTANT: The HTML files are ~300KB each with inline JSON DATA blobs. Do NOT try to rewrite the whole file. Use targeted sed/python replacements on the specific data lines.

### Avoiding Data Regression
Other agents (analyst) and manual edits sometimes add new sections to the HTML files (e.g., watch list tables, new chart sections). These commits may inadvertently revert YOUR data values if they were based on a stale copy of the file. Conversely, YOUR edits must not revert THEIR structural additions. The rule is:
- **Your job is data values** — update numbers, counts, dates, and chart data arrays
- **Preserve structure** — don't delete or overwrite sections you didn't create
- **Use targeted replacements** (sed/python on specific lines), never whole-file overwrites

The key variables to target:
- `const mActualCve = {...}`
- `const mKevLookup = {...}`
- `const mConservative = ...`
- `const mAggressive = ...`
- The mythosCveChart labels and data arrays
- The dashPatchChart labels and both dataset data arrays
- `const mMonthsAll = [...]`
- **`DATA.total_kev`** — set to `len(catalog['vulnerabilities'])` from the KEV JSON you already fetched. This drives the "X exploited vulnerabilities" subtitle, the "KEV Entries (Total)" KPI tile, and several prose mentions via `<span data-kpi="totalKev">` placeholders. Both `docs/dashboard.html` and `docs/index.html` carry their own DATA blob — update both. If the test suite (`tests/run.sh`) reports `DATA.total_kev != classifications JSON entry count`, you've drifted; reconcile before pushing.

## TRACKING FILE
Write a `kev-tracking.json` to the repo root (`kev-repo/kev-tracking.json`) AND to `/mnt/outputs/` (for local access) with:
```json
{
  "last_run": "ISO timestamp",
  "data_collected": {
    "overall_cve": { "month": "YYYY-MM", "mtd_count": N, "extrapolated": N, "days_elapsed": N },
    "kev_additions": { "month": "YYYY-MM", "count": N, "notable_entries": ["..."], "new_np_di_entries": ["..."] },
    "glasswing_cves": { "total": N, "by_product": {"Firefox": N, "wolfSSL": N}, "new_since_last": N },
    "ms_patch_tuesday": { "latest_month": "YYYY-MM", "count": N },
    "rhel8_errata": { "latest_month": "YYYY-MM", "count": N },
    "weekly_cve": { "YYYY-Www": N }
  },
  "exploit_intelligence": {
    "watch_list_status": {
      "CVE-YYYY-NNNNN": {
        "exploitdb": { "found": false },
        "metasploit": { "found": false },
        "github_poc": { "found": false, "repo_count": 0 },
        "overall_maturity": "none|poc|functional|weaponized",
        "last_checked": "ISO timestamp"
      }
    },
    "newly_escalated": ["list of CVEs that changed maturity level since last run"],
    "summary": "N of M watch list CVEs have public exploits. N newly escalated."
  },
  "mythos_monitoring": {
    "google_news_hits": [
      { "headline": "...", "source": "...", "date": "...", "cves": ["..."], "products": ["..."] }
    ],
    "vendor_advisory_flags": [
      { "vendor": "...", "cve": "...", "product": "...", "meets_self_scan_criteria": true, "notes": "..." }
    ],
    "new_participant_products": ["any new products/vendors seen in Glasswing context"]
  },
  "np_di_candidates": [
    { "cve": "...", "product": "...", "cwe": "...", "recommendation": "add_to_watchlist|monitor|skip", "rationale": "..." }
  ],
  "projection_comparison": {
    "current_month": "YYYY-MM",
    "actual_or_extrapolated": N,
    "conservative_predicted": N,
    "aggressive_predicted": N,
    "verdict": "below_conservative | on_track_conservative | between | above_aggressive"
  },
  "changes_pushed": true,
  "commit_sha": "abc123",
  "errors": []
}
```

## ALSO UPDATE config.json
After collecting fresh data, update:
- `baseline_data` section with any new monthly values
- `exploit_intelligence` section with exploit check results for all watch list CVEs
- Watch list CVE statuses if any moved to "confirmed" (appeared in KEV)

## WALKTHROUGH (docs/index.html) UPDATES
The walkthrough has prose descriptions of the Mythos data. Update:
- The monthly CVE baseline table/text
- The "~40 CVEs linked to Glasswing" count if it's changed
- The Microsoft/RHEL patch velocity numbers
- The projection comparison narrative

## ERROR HANDLING
- If NVD API returns 429, wait 10 seconds and retry once. If still failing, use alternate sources.
- If GitHub push fails (403/auth), save all changes locally and report in tracking JSON.
- If a data source is unavailable, use the last known value from config.json and flag it.
- If ExploitDB or Metasploit searches fail, note in errors array but don't block the rest of the run.
- Always produce the tracking JSON even if some data sources fail.

## COUNTER-ARGUMENTS (important)
When reporting findings, always note the counter-argument. For example:
- If CVE volume hasn't spiked: "NVD publishing latency is 4-8 weeks; Glasswing discoveries may not appear yet"
- If volume has spiked: "Correlation isn't causation; other factors (batch disclosures, new researchers) could explain it"
- If KEV additions spike: "CISA KEV additions are editorial decisions, not purely volume-driven"
- If exploit maturity is low for watch list CVEs: "Absence of public PoC doesn't mean no exploitation — state actors use private exploits"
- If vendor advisories match self-scan pattern: "Internal-discovery can happen without AI; correlation with Glasswing timing is suggestive, not causal"

## WEEKLY GRANULARITY (April/May 2026)
For the current month and the next month, also track weekly CVE counts to give more granular visibility into whether there's a post-Glasswing inflection point. Store weekly data in the tracking JSON under `data_collected.weekly_cve`.

## EXECUTION ORDER
To manage rate limits and prioritize the most important data:
1. **NVD + KEV** (steps 1-2) — core data, do first
2. **OSV scan** (step 14, source 3) — query OSV API for recent C/H advisories in NP packages (~30 queries at 1/sec)
3. **Glasswing search** (step 3) — depends on web search, may be slow
4. **Exploit intelligence** (steps 8-11) — iterate through watch list, one CVE at a time, with 2-3 second pauses between web searches to avoid rate limits
5. **Vendor advisories** (step 13) — batch of web searches, pace them
6. **Google News** (step 12) — 7 search queries, pace them
7. **NP+DI candidate scan** (step 14, filter pass) — apply NP+DI filter to NVD + KEV + OSV results collected above
8. **Patch Tuesday + RHEL** (steps 4-5) — check once, quick
9. **Projections + timeline** (steps 6-7) — compute from collected data
10. **Write tracking JSON, update HTML, commit, push**
