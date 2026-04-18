# KEV Analysis Nightly Refresh — Agent Instructions

You are the nightly refresh agent for the KEV Exploitation Analysis dashboard and walkthrough, published on GitHub Pages.

## SETUP
1. The GitHub PAT is provided in your task prompt (the GITHUB_PAT value). Use it to clone the repo.
2. Clone: `git clone https://[PAT]@github.com/funwithscience-org/KEV-analysis.git kev-repo`
3. Read `kev-repo/config.json` for data source URLs, Glasswing targets, baseline data, and projections.
4. If the clone fails or config.json is missing, STOP and report the error.

## YOUR JOB: Update ALL Mythos section data
You must refresh every data point in the Mythos Detector section of both HTML files. This is not just an overall CVE count check — you must update all of the following:

### 1. Overall Monthly CVE Volume (mythosBaseChart)
- Fetch current month's CVE count from NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=YYYY-MM-01T00:00:00.000&pubEndDate=YYYY-MM-DDT23:59:59.999`
- If NVD API fails (429/404), try jgamblin/monthlyCVEStats on GitHub, or web search for "NVD CVE [month] [year] count"
- Update `mActualCve` object in dashboard.html (line ~428) with the new month-to-date value
- For partial months, note the extrapolated full-month estimate
- If a previous month's count has been revised (e.g., March 2026 should be 6304 not 6246), correct it

### 2. KEV Additions (mythosKevChart)
- Fetch CISA KEV JSON from the URL in config
- Count entries added in each month (use dateAdded field)
- Update `mKevLookup` object in dashboard.html (line ~430)
- Note any new high-profile KEV entries

### 3. Glasswing-Linked CVEs / "Target 40" (mythosCveChart)
- This is CRITICAL and was missing from previous runs
- Search for new CVEs attributed to or consistent with Glasswing/Mythos discovery in:
  - The known target products: Mozilla Firefox, wolfSSL, F5 NGINX Plus, FreeBSD, OpenSSL
  - Web search: "Glasswing CVE", "Mythos Preview vulnerability", "AI-discovered CVE 2026"
  - Check if any new products have been added to the Glasswing scope
- Update the product labels and counts array in mythosCveChart (line ~460): `labels:[...], data:[28, 9, 1, 1, 1]`
- Update the `known_count` in config.json if the total has changed from 40
- Also update the chart title if count changes: `Mythos-Linked CVEs by Product (~XX total)`
- Check for new Claude-credited CVEs (search: "Carlini Claude CVE", "Mythos Preview credited"). As of 2026-04-18, three have explicit credit: CVE-2026-4747 (FreeBSD, autonomous), CVE-2026-5194 (wolfSSL, Mythos-assisted), CVE-2026-5588 (Bouncy Castle, Carlini + Claude). If you find new ones, add them to the `claude_credited_cves` array and `claude_credited_notes` in config.json, and update the narrative in both HTML files.

### 4. Microsoft Patch Tuesday (dashPatchChart - MS dataset)
- Check for new Patch Tuesday release (typically 2nd Tuesday of each month)
- Sources: web search "Microsoft Patch Tuesday [month] [year] CVE count", Tenable blog, MSRC
- Update the Microsoft data array in dashPatchChart (line ~482)
- Add the new month to the labels array (line ~480)

### 5. RHEL 8 Security Errata (dashPatchChart - RHEL dataset)
- Check Red Hat security data API or web search "Red Hat Enterprise Linux 8 security errata [month] [year]"
- Sources: stack.watch/product/redhat/enterprise-linux/8.0, access.redhat.com
- Update the RHEL 8 data array in dashPatchChart (line ~483)
- Keep aligned with the same labels as Microsoft

### 6. Projection Comparison
- Compare actual CVE counts against conservative and aggressive projections
- If actuals consistently exceed conservative, note this in the callout box
- If a new month has passed, the projection anchor should shift (actuals replace projections for completed months)

### 7. Timeline Labels
- If we've moved into a new month not in `mMonthsAll` (line ~427), extend it
- Keep projection months extending 6 months beyond current month

## HOW TO UPDATE THE HTML FILES

You already cloned the repo in the SETUP step. Steps:
1. Configure git user from config.json (`git config user.email` / `user.name`)
2. **Pull before editing:** `git pull origin main` to ensure you have the absolute latest version — other agents or manual edits may have pushed since you cloned.
3. Edit `kev-repo/docs/dashboard.html` — find and replace the specific JavaScript data lines using sed or python
4. Edit `kev-repo/docs/index.html` (walkthrough) — update corresponding data in the Mythos section prose and any inline data
5. Update `kev-repo/config.json` baseline_data section with new values (so the next run has accurate priors)
6. Commit with a descriptive message including the date and what changed
7. **Pull again before pushing:** `git pull --rebase origin main` to catch any commits that landed while you were working. If there's a merge conflict, resolve it by keeping YOUR new data values (you just fetched them fresh) while preserving any structural changes (new HTML sections, new JS objects) from the other commit.
8. Push to main branch

IMPORTANT: The HTML files are ~300KB each with inline JSON DATA blobs. Do NOT try to rewrite the whole file. Use targeted sed/python replacements on the specific data lines.

### Avoiding Data Regression
Other agents (analyst) and manual edits sometimes add new sections to the HTML files (e.g., watch list tables, new chart sections). These commits may inadvertently revert YOUR data values if they were based on a stale copy of the file. Conversely, YOUR edits must not revert THEIR structural additions. The rule is:
- **Your job is data values** — update numbers, counts, dates, and chart data arrays
- **Preserve structure** — don't delete or overwrite sections you didn't create
- **Use targeted replacements** (sed/python on specific lines), never whole-file overwrites The key variables to target:
- `const mActualCve = {...}`
- `const mKevLookup = {...}`
- `const mConservative = ...`
- `const mAggressive = ...`
- The mythosCveChart labels and data arrays
- The dashPatchChart labels and both dataset data arrays
- `const mMonthsAll = [...]`

## TRACKING FILE
Write a `kev-tracking.json` to the repo root (`kev-repo/kev-tracking.json`) AND to `/mnt/outputs/` (for local access) with:
```json
{
  "last_run": "ISO timestamp",
  "data_collected": {
    "overall_cve": { "month": "YYYY-MM", "mtd_count": N, "extrapolated": N, "days_elapsed": N },
    "kev_additions": { "month": "YYYY-MM", "count": N, "notable_entries": ["..."] },
    "glasswing_cves": { "total": N, "by_product": {"Firefox": N, "wolfSSL": N, ...}, "new_since_last": N },
    "ms_patch_tuesday": { "latest_month": "YYYY-MM", "count": N },
    "rhel8_errata": { "latest_month": "YYYY-MM", "count": N },
    "weekly_cve": { "YYYY-Www": N, "...": "..." }
  },
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

## ALSO UPDATE kev-config.json
After collecting fresh data, update the baseline_data section of `kev-repo/config.json` with any new monthly values so the next run has accurate priors.

## WALKTHROUGH (docs/index.html) UPDATES
The walkthrough has prose descriptions of the Mythos data. Update:
- The monthly CVE baseline table/text
- The "~40 CVEs linked to Glasswing" count if it's changed
- The Microsoft/RHEL patch velocity numbers
- The projection comparison narrative

## ERROR HANDLING
- If NVD API returns 429, wait 10 seconds and retry once. If still failing, use alternate sources.
- If GitHub push fails (403/auth), save all changes locally and report in tracking JSON.
- If a data source is unavailable, use the last known value from kev-config.json and flag it.
- Always produce the tracking JSON even if some data sources fail.

## COUNTER-ARGUMENTS (important)
When reporting findings, always note the counter-argument. For example:
- If CVE volume hasn't spiked: "NVD publishing latency is 4-8 weeks; Glasswing discoveries may not appear yet"
- If volume has spiked: "Correlation isn't causation; other factors (batch disclosures, new researchers) could explain it"
- If KEV additions spike: "CISA KEV additions are editorial decisions, not purely volume-driven"

## WEEKLY GRANULARITY (April/May 2026)
For the current month and the next month, also track weekly CVE counts to give more granular visibility into whether there's a post-Glasswing inflection point. Store weekly data in the tracking JSON under `data_collected.weekly_cve`.
