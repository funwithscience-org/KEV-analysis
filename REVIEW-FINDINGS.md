# Independent Review Findings — April 23, 2026

## Reviewers Run
1. **Hacker (#2)** — single pass, complete
2. **Fresh Analyst (#4)** — single pass, complete
3. **Data Freak (#1)** — Pass 1 (dashboard), Pass 2 (charts+walkthrough), Pass 3 (hardcoded audit) — complete
4. **Curmudgeon (#3)** — Pass 1 (§1-4), Pass 2 (§5-9), Pass 3 (dashboard standalone), Pass 4 (overall) — complete

## Remaining Passes Not Yet Run
- Data Freak Pass on periodicity page (charts/tables specifically)
- Curmudgeon never reviewed the OSV exploitation scratch page or evergreen page

## Confirmed Bugs (Fixed)
- 934→886 windowed KEV count (ratio estimation error; actual is 886 from JSON)
- 1,577→1,578 total KEV (refresh agent added entry)
- 4.0%→3.8% overall rate
- Ransomware "313" in prose was unwindowed stale number

## Confirmed Bugs (Still Open)
- Ransomware prose says "186" but DATA blob has 191 (186=ground truth, 191=ratio estimate in blob)
- Walkthrough §7c heading says "Spring 59%" but table says 64%
- Walkthrough stat box says "2-4 NP+DI" should be "2-6"
- Walkthrough firmware prose says "5 KEV, 0.13%" should be "4 KEV, 0.11%"
- Cross-page reduction range: dashboard "59-86%", walkthrough has "71-86%" in one place — true range is 64-86%

## Architecture Recommendation (Data Freak)
- Single shared data.js file loaded by all pages
- Generate static tables from DATA blob on page load
- Compute KPI tiles/prose from DATA blob into <span> placeholders
- Add periodicity DATA blob (currently 6 hardcoded arrays, 2 static tables)
- CVE reference summary tiles should count from DOM

## Structural Critiques

### Circularity / Curve Fitting (Curmudgeon + Fresh Analyst)
- CWE set built from historical exploitation, tested against same data
- "Zero misses" is unfalsifiable when misses are blamed on CWE metadata
- Widened DI (adding auth bypass) looks like goalpost-moving
- **Author reframing:** This is a minimum-action triage policy, not a predictive model. Built from "what has burned people." The real risk is missing novel patterns, not circularity.
- **Resolution:** Reframe language throughout from "predicts" to "triages." Forward-validate against new inbound. Mythos surge is a unique opportunity for validation — both signal and noise.

### Survivorship Bias (Fresh Analyst + Curmudgeon)
- KEV is government-biased, OSV is public-exploit-biased
- jackson-databind zero-exploitation may reflect attacker preference, not impossibility
- **Acknowledge:** Lift is measured relative to observable exploitation; may overstate gap if non-NP exploitation is under-reported

### Temporal Fragility (Fresh Analyst)
- 3-6x lift on 2021-2026 only. Pre-2021 (Flash, Java applets) might show different distribution.
- Mythos era may create unique patterns — tracking against it is the right call

### AI Scan Tier (Curmudgeon)
- "Have an AI look at it" isn't a reproducible filter
- The simplicity selling point is gone once you add AI review
- **Counter:** AI scan has a documented query (see OSV exploitation page §7). It's reproducible, just not rule-based.

## Hacker Attack Paths (Prioritized)
1. Stored XSS → admin session theft (Tier 3, 30-day window, WAF-invisible)
2. jackson-databind deserialization (permanently deprioritized, one gadget chain away)
3. Supply chain bypass (outside entire framework — no CVE until after discovery)
4. Container escape via monthly OS gap (foothold + kernel CVE)
5. Tier 2 semantic bypass (header manipulation, 1-2 week window)
6. Info disclosure → credential harvest (actuator endpoints, Tier 3)

## Curmudgeon Final Grades
- Intellectual honesty: B+
- Data rigor: B-
- Operational usefulness: A-
- Presentation quality: B-
- Overall: B
- Verdict: "Would adopt as triage accelerator with conditions"

## Punch List (Priority Order)
1. Reframe methodology as triage policy, not predictive model — use "natural hygiene" not "30 days"
2. Forward-validate against new inbound (don't freeze CWE set yet — Mythos surge is validation opportunity)
3. Compute values from data, don't hardcode (shared data.js architecture)
4. Add changelog/errata to dashboard
5. Fix remaining text errors (5 open bugs above)
6. Add sample sizes (n-counts) to rate charts
7. Resolve cross-page denominator confusion (library 17.5% vs 0.05%)
8. Glasswing extraction: DONE (moved to glasswing.html)

## Framing Notes (Steve)
- Not a theoretical prediction — trying to pick a conservative path with least actions that is never wrong
- The risk isn't curve fitting, it's missing something that hasn't happened yet
- Forward validation: (1) validate against new inbound, (2) Mythos is a unique surge — look for signal AND noise — potentially creating work we can't do simultaneously
- Use "natural hygiene" not specific timelines for the non-emergency tier
- Auth bypass DI additions are not goalpost-moving — they're miscategorized DI that we corrected
