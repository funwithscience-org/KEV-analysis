# FOSS sub-7 model backtest — does the C/H model give medium coverage for free?

**Date:** 2026-04-29
**Input:** `data/foss-low-severity-exploited.json` (135 distinct CVEs, CVSS < 7.0, server-side FOSS, with KEV / Metasploit / ExploitDB exploitation evidence)
**Output:** `data/foss-sub7-model-scoring.json`
**Question:** Built on Crit/High historicals, does the threat-prioritization model (NP+DI structure test, DQ rescue, hacker S/A tier) generalize down to medium-severity FOSS CVEs? If yes, the same filters give medium coverage as a free side effect of running on C/H.

---

## Headline catch rates (n = 135)

| Filter | Caught | Rate |
|---|---|---|
| **NP+DI raw** | 111 | **82.2%** |
| **NP+DI+DQ** | 116 | **85.9%** |
| **Hacker S+A** | 35 | **25.9%** |
| **Union (either)** | 118 | **87.4%** |
| **Intersection (both)** | 32 | 23.7% |

Tier distribution: S 9, A 26, B 85, D 15.

**Free-coverage verdict:** *Mixed, leaning yes-with-caveats.* The structure test (NP+DI / NP+DI+DQ) catches 82–86% of exploited mediums — a strong number that says the same filter applied to the same packages would surface most of the medium-exploited population without extra triage cost. The hacker S+A overlay catches only 26%, but that's *intended* — the hacker test is supposed to be picky, and at sub-7 CVSS most bugs are not S/A operator material by construction. The union is 87%, slightly above NP+DI+DQ alone — hacker adds two CVEs the structure test misses (slo-generator code injection on a non-NP CLI tool; Elasticsearch error message leak that's NP but not DI).

But: **read the "weaker signal" caveat below before celebrating the 86% number.** The structure test in this dataset is essentially "NP=True for almost everything" — 97 of 98 distinct packages are NP — so NP+DI collapses into "does the bug have an injection-class CWE." That's still useful, but it's a much weaker discriminator than it looked in the Crit/High population.

---

## Breakdown by ecosystem

| Ecosystem | n | NP+DI | NP+DI+DQ | Hacker S+A | Union |
|---|---|---|---|---|---|
| Maven | 45 | 75.6% | 80.0% | 28.9% | 84.4% |
| Packagist | 53 | 81.1% | 86.8% | 20.8% | 86.8% |
| PyPI | 23 | 87.0% | 87.0% | 21.7% | 91.3% |
| Go | 6 | 83.3% | 83.3% | 50.0% | 83.3% |
| npm | 5 | 100% | 100% | 40.0% | 100% |
| NuGet | 2 | 100% | 100% | 50.0% | 100% |
| RubyGems | 1 | 100% | 100% | 0.0% | 100% |

PyPI and Packagist (both heavy in CMS/web-app monoliths) catch slightly higher than Maven, where Jenkins plugins, Liferay portlets, and BouncyCastle drag the rate down. Go's 50% S+A rate is a small-N artifact (3 of 6 are direct primitives).

---

## Breakdown by evidence source

| Source | n | NP+DI | NP+DI+DQ | Hacker S+A | Union |
|---|---|---|---|---|---|
| **KEV** | 4 | 50% | 50% | 0% | 50% |
| Metasploit | 18 | 88.9% | 88.9% | 55.6% | 94.4% |
| ExploitDB | 124 | 82.3% | 86.3% | 26.6% | 87.9% |

**KEV (the strongest signal) is the worst result.** Two of four KEV-confirmed mediums are missed entirely. The four KEVs are:
- CVE-2020-11652 (salt path traversal) — caught by NP+DI, hacker B (auth required)
- CVE-2023-44487 (HTTP/2 Rapid Reset DoS) — missed: DoS-only, no DI CWE, hacker D
- CVE-2025-31125 (vite path traversal via `?import`) — caught by NP+DI, hacker B (default-config off, only when --host is used)
- CVE-2025-35939 (Craft CMS unauth content stored in session files) — missed: chained primitive, no DI CWE, hacker D

The two misses are both genuine model limitations, not classification errors. Rapid Reset is a structural HTTP/2 weakness (DoS); the model correctly de-prioritizes DoS as a primitive. Craft CMS session-file storage is a chain-primitive: storing arbitrary content + an independent vulnerability to read/execute the file = bad. The model treats step-1-only chains as B/D, which is consistent.

**Metasploit catch rate is ~89%** — these are bugs someone bothered to weaponize, and they trend toward direct primitives.

---

## S-tier and A-tier mediums (the actionable "should we have caught this?" list)

### S-tier (9)

These are all-three-axes + auth_missing — operator-deployable day-1 primitives at sub-7 CVSS.

- **CVE-2009-0815** (typo3/cms, CVSS 6.9): juHash secret leaks via error message; chains to arbitrary file read.
- **CVE-2009-1523** (org.mortbay.jetty:jetty, CVSS 5.3): Directory traversal via URI.
- **CVE-2010-5099** (typo3/cms, CVSS 6.6): Path traversal that reads encryption key, leads to full compromise.
- **CVE-2011-1571** (com.liferay.portal:portal-service, CVSS 6.9): Unauth arbitrary command injection.
- **CVE-2014-8681** (gogs, CVSS 6.5): SQLi in `GetIssues` via the `label` parameter.
- **CVE-2019-17554** (org.apache.olingo, CVSS 5.5): XXE on default OData XML deserialization — file read.
- **CVE-2020-28413** (mantisbt/mantisbt, CVSS 5.3): SQLi in SOAP API `mc_project_get_users` `access` parameter.
- **CVE-2021-22557** (slo-generator, CVSS 5.3): YAML-driven code injection. *Not caught by NP+DI* — non-NP package.
- **CVE-2025-59342** (esm.sh, CVSS 5.5): Path traversal arbitrary file write via `X-Zone-Id` header on `POST /transform`.

### A-tier (26 — top 10 by surface and recency)

- **CVE-2025-47226** (snipe/snipe-it, CVSS 5.0): IDOR on asset information.
- **CVE-2025-34076** (microweber/microweber, CVSS 6.1): Authenticated LFI via backup management API.
- **CVE-2025-30208** (vite, CVSS 5.3): `server.fs.deny` bypass via `?raw??`.
- **CVE-2024-46528** (kubesphere, CVSS 6.5): IDOR allowing access to sensitive resources.
- **CVE-2023-40028** (ghost, CVSS 4.9): Arbitrary file read via symlinks in content import.
- **CVE-2023-39265** (apache-superset, CVSS 6.5): SQLite driver-name registration bypass.
- **CVE-2021-34429** (jetty, CVSS 5.3): Encoded-URI WEB-INF access.
- **CVE-2021-28164** (jetty, CVSS 5.3): Authorization-before-canonicalization variant.
- **CVE-2021-22145** (elasticsearch-rest-client, CVSS 6.5): Memory disclosure via error message — auth details leak.
- **CVE-2020-10770** (keycloak-core, CVSS 5.3): SSRF via OIDC `request_uri`.

The remaining A-tier are CMS path-traversals (OpenCMS, OpenMeetings, WSO2, Cherry Music, Umbraco, Moin twikidraw, October CMS), Spring Cloud Config arbitrary-config-file traversal, Moodle SSRF, Pimcore REST API SQLi, Shopware XXE→PHP-object-instantiation in admin backend, phpMyAdmin XML-import XXE, and the PHPMailer `msgHTML` local file disclosure.

The S/A list is the cleanest answer to "should we have caught these in the C/H workflow but missed because of the severity filter?" — yes, all of them satisfy the model's "act" criteria, and most have CVSS in the 4.3–6.9 range.

---

## The "free coverage" angle, honestly

If the model is going to be applied to the C/H pipeline anyway, the same filter pass costs nothing extra at sub-7. **NP+DI+DQ catches 86% of the exploited-medium population at zero marginal triage cost** — that's the headline. The 14% it misses are mostly:

- DoS-class HTTP weaknesses (Rapid Reset; Tomcat priority-header memleak)
- CSRF-only bugs in admin panels (4 cases — phpMyAdmin x2, web2py, yourls, Casdoor)
- Open redirects (Tomcat default servlet, Spring Security OAuth, PluggableAuth)
- Pure info-disc bugs that the model intentionally rejects (BouncyCastle Bleichenbacher oracle, Drupal full-path-disclosure, Jenkins SonarQube cleartext password, Apache Axis WSDL path leak, Apache Syncope sensitive value exposure)
- Two chain-primitive bugs the model treats as not-direct (Craft CMS session storage; phpMyFAQ iframe download)
- One CSV injection (RosarioSIS)
- One brute-force-on-login (Soosyze)

Those 18 misses are *the same shape as the misses in the Crit/High backtest*: DoS, info-disc, CSRF, open redirect, chained primitives. The model's miss profile generalizes faithfully. That's the strongest argument that this isn't a coincidence — the same blind spots show up at the same rate.

**Hacker S+A (26%) is much pickier.** That tracks: at sub-7 CVSS, most bugs are *defined out* of S/A by the way the rule works (XSS, CSRF, open redirect, info-disc all cap at B regardless of axes; only direct-primitive bugs can reach S/A). Hacker S+A is the "should we sound the alarm?" filter and almost no medium reaches that bar. The 35 that do (9 S + 26 A) are real action-worthy mediums that the C/H severity filter would skip.

---

## The other side of the argument — is this a real signal or NP-package-laundering?

**This is the point that deserves the most scrutiny.** Of 98 distinct packages in this dataset, **97 are classified NP** (the only non-NP package is `slo-generator`, a Google YAML CLI tool). That means NP=True is essentially a tautology on this dataset — every package that ships server-side and gets exploited is by definition processing untrusted network input.

So when I report "NP+DI catches 82.2%," what I really mean is:

> 82.2% of exploited sub-7 server-side CVEs have a CWE in the DI set (injection / path traversal / SSRF / XXE / auth-bypass / deserialization).

The NP gate isn't doing discriminating work here. It would be doing work if the universe also contained, say, SQLi bugs in pure data-processing libraries (numpy, pandas), CWE-89 bugs in batch ETL tools that never see user input, etc. — those would fail NP and be filtered out. They're not in the dataset because the dataset was already pre-filtered to `server_side: true`.

**This means two things:**

1. The 86% NP+DI+DQ headline is more like an "ecosystem-shape" number than a "filter discriminator" number. It tells you the dominant primitives at sub-7 in server-side FOSS are injection / path traversal / auth-bypass — which is reassuring for the model's design intent (it was built to find exactly these patterns). But it doesn't tell you the filter is doing better than "match the bug shape."

2. The Crit/High C/H result (NP+DI 6/13, NP+DI+DQ 9/13) is a *stronger* signal than the medium 82% because the C/H denominator naturally contains more variety of bug shapes — kernel privesc, OS-layer auth bugs, image-decoder memory corruption, etc. — that fail NP. At medium, the universe is already pre-filtered to server-side, so NP doesn't do the same work.

**The honest "free coverage" framing:** The model generalizes down to mediums in the sense that *when applied unchanged to medium server-side CVEs, it identifies the same kinds of bugs it identifies at C/H*. That's free coverage — useful, real. But the discriminator strength at medium is weaker because the universe is shaped differently. You're getting "this is an injection-class bug" labeling for free, not "this is the bug shape we care about" filtering.

**The hacker-tier overlay is the actual filter at this severity tier.** S+A catches 26%, and that 26% is genuinely picked out of a 135-CVE pool by per-CVE merit (default config + network edge + direct primitive + auth_missing). Hacker S+A is doing the discriminating work at sub-7 that NP+DI does at C/H.

---

## Honest concerns about my own classifications

1. **Auth_missing is text-keyword-driven and noisy.** I mark `auth_missing=False` when the summary contains words like "authenticated," "with permissions," "admin," "/admin/," "soap api," "controllers_backend." This catches most cases but misses contextual auth requirements that aren't stated explicitly (e.g., a SOAP API that requires a session token isn't always called out). Conversely, summaries that say "remote attackers" but actually require a CSRF-style victim click get marked unauth. If 5–10 borderline auth calls flipped, S-tier would shift by 1–3 entries. Most likely flips: CVE-2018-14058 (Pimcore REST SQLi — short summary, may actually be unauth), CVE-2025-47226 (Snipe-IT IDOR — definitely auth required, classified correctly), CVE-2017-18357 (Shopware backend — currently auth required, correct).

2. **Default_config is also text-driven and over-credits "reachable" as "default."** When a summary doesn't *explicitly* say "non-default," I mark default=True. This probably over-counts default_config across the board. If I were stricter, several A-tier path-traversal bugs would drop to B (e.g., the OpenCMS `logfileViewSettings.jsp` is admin-panel-only — already caught by auth_required, but the *endpoint* is admin-only, not "the default Tomcat install"). The S-tier list would lose nothing because S-tier bugs are explicit primitives on default-shaped code paths.

3. **The XSS-floor cap is a judgment call, not a mechanical rule.** I cap XSS / CSRF / open-redirect / info-disc / DoS / CSV / brute-force / prototype-pollution / improper-input-val at tier B regardless of axes, on the v2-report rationale that "primitive-directness is the dominant axis." A reviewer could argue strictly per-the-brief that an unauth default-config XSS on a CMS admin panel hits 2 axes + auth_missing = A. If I removed that cap, A-tier would balloon (~78 entries) and S+A would jump to ~65%. I think the cap is correct for an operator framing — operators don't deploy XSS as a campaign primitive against random CMSes — but reasonable people disagree. The cap is the single biggest sensitivity in the headline number.

4. **DI inference is regex-on-text, not OSV CWE lookup.** I didn't re-fetch OSV CWE IDs for each CVE; the input dataset doesn't include them, so I infer CWE class from summary/details text. Most cases are unambiguous (the word "XSS" or "SQL injection" or "directory traversal" appears in the summary). But a few cases where the summary is short ("Pimcore SQLi Vulnerability") inherit the CWE confidently from the keyword match. If I'd done OSV lookups I'd have higher confidence on the borderline cases (~5 entries with kinds=`unknown`).

5. **The NP-package list is judgment-driven, especially the CMS-monolith-as-NP call.** I treat every CMS / web-app monolith (TYPO3, Drupal, Liferay, Concrete5, etc.) as NP because they own the HTTP boundary. A stricter reading would say "CMS is a *consumer* of an HTTP framework, not a parser library" — under that reading, only Spring/Tomcat/Jetty/Django itself is NP and the CMS-on-top is not. That stricter reading would drop NP+DI to maybe 30% and the headline would invert. I think CMS-as-NP is correct under the formalized rule's "trust boundary" framing — the CMS *is* the HTTP server in operational reality — but it's the second-biggest sensitivity after the XSS-cap.

---

## What would change the headline meaningfully

- If I removed the XSS-floor cap: NP+DI+DQ unchanged (86%), Hacker S+A jumps from 26% → ~60%. The structure result is robust; the hacker result isn't.
- If I treated CMS-monoliths as non-NP: NP+DI drops to ~30%, hacker unchanged.
- If I tightened auth_missing keyword detection: 3–5 S-tier entries demote to A, A-tier drops a similar number to B. Hacker S+A would drop a couple of percentage points but not the headline shape.
- If I used OSV CWEs instead of text inference: probably ±2 entries in NP+DI raw count.

The 80%+ structure-test catch rate is robust under any reasonable parameter sensitivity *as long as you accept CMS-monoliths-as-NP*. The hacker S+A 26% is sensitive to the XSS cap and the auth_missing detection.

---

## Mythos check — sub-7 CVEs with S-tier shape

The S-tier list above is the answer. The 9 entries are all default-config × network-edge × primitive-direct × unauth on server-side packages. By the model, these would have been auto-prioritized at C/H severity. Any operator running the Mythos preview against any of these packages would have surfaced these bugs as "high-priority structural matches." If we're missing them in the C/H workflow because of the severity filter, the cost is real — these are exactly the kinds of bugs Mythos-style scanners are supposed to flag.

The most operationally interesting modern S-tier:
- **CVE-2025-59342 (esm.sh)** — header-driven path traversal arbitrary write on a Go module CDN. Single-shot, deterministic, network-edge.
- **CVE-2021-22557 (slo-generator)** — YAML code-injection. Slo-generator is a small Google tool but the pattern (untrusted YAML → code exec) is widespread.
- **CVE-2020-28413 (MantisBT SOAP SQLi)** — exposed SOAP endpoints exist in many enterprise installs.

---

## Files

- **Per-CVE scoring (135 records):** `/sessions/bold-nice-euler/mnt/vulnerability analysis/data/foss-sub7-model-scoring.json`
- **This report:** `/sessions/bold-nice-euler/mnt/vulnerability analysis/analyst-reports/2026-04-29-foss-sub7-model-backtest.md`
- **Source classifier:** `/sessions/bold-nice-euler/classify.py` (text-inference rule set + per-package NP map)
