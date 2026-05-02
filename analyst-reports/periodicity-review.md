# Periodicity Analysis & Walkthrough Restructuring — Internal Review (2026-05-02 pass)

**Author:** kev-analyst (scheduled run)
**HEAD at review:** `ffcc165` (today's tracking commit; analytic HEAD `fabf4f8` "refresh agent 2026-05-02: KEV catalog 2026.05.01 (1587 entries, +CVE-2026-31431 Linux Kernel)")
**Predecessor pass:** `71b642a` periodicity-review.md from 2026-05-01 (this is the eleventh analyst-side review; earlier passes preserved as `periodicity-review-pass5.md` … `pass8.md`).
**Inputs reviewed:** `docs/periodicity.html`, `docs/index.html`, `docs/dashboard.html`, `docs/cve-reference.html`, `config.json`, `kev-tracking.json`, `data/post-apr1-per-framework.json` (via embed in dashboard.html), the 2026-05-01 → 2026-05-02 commit set (16 commits, including the DI CWE freeze and the live tracker).

---

## 0. Headline (read this if you read nothing else)

**The largest analytic shift since the last review is the May-1 DI CWE freeze plus the live-tracker that turns the project from "filter we built and validated retroactively" into "filter we have committed to and are scoring publicly going forward."** That's two of the three big asks from the May-1 review landed in roughly 24 hours (commit `06a7192` froze the 31-CWE set on the dashboard with a since-freeze counter; the live tracker chain `c3cd028 → 08dda4d → 5d27eaf → a580712 → 4fe4c00 → 1442ae3` builds the operational ledger that fills the counter, and now ties into the daily refresh agent so it doesn't quietly go stale). The third ask — the walkthrough narrative reorder (move §5 survivorship and §6 time-to-exploit ahead of §3 model) — has *not* landed; the walkthrough is still in observation → model → validation → backfill order. That edit is the highest-leverage remaining piece of writing in the project.

The review brief (`analyst-reports/periodicity-review-brief.md`) describes a pre-restructure walkthrough that no longer exists. Most of what the brief asked for — three-tier model integration, periodicity content, OS chaining, external validation — is already in the walkthrough. The brief's frame ("a major new analysis has been published… the walkthrough has not been updated to reflect this") is now five passes stale. The review value today is in (a) assessing the new freeze + live-tracker work, (b) flagging the still-pending walkthrough reorder, (c) identifying overclaim/underclaim around the freeze counter while it's at zero events, and (d) the daily scan addendum.

The dashboard has had two big surgeries in 24 hours: the **hero KPI swap** (251d→11d demoted, 10/11 union promoted — `51acec3`) and the **live tracker** taking the marquee real-estate immediately below the freeze counter. Both are right calls. The hero KPI swap was the May-1 review's recommendation D4 verbatim. The live-tracker now serves as the operational receipt that the freeze counter ledger tracks. Net read: **the dashboard is in materially better operational shape than it was 24 hours ago**, with two pending tightenings (see §3.2).

The freshest analytic gap, present today and worth flagging early: **the freeze counter shows 0/0/0 across all six tiles because there have been zero post-freeze events in the live tracker's NP+DI window.** That is correct on day 1, but a reader landing now sees "0 caught, 0 missed, 0 events scored" and the `freezeUnion` and `freezeMissed` tiles look indistinguishable from "filter is doing nothing." See §3.4 for the recommended pre-data framing — a single explanatory caption above the tile grid, not a content change.

---

## 1. Assessment of the periodicity analysis (current HEAD)

### 1a. What is sound, on this pass

The 2026-05-01 review's §1a framing largely holds. **The 7-year backtest is still the heart of the work** (194 C/H, 11 actually exploited, 4 strategies scored, union 10/11 directly + 1 supplements). **Cross-framework still reproduces the workload claim** (Spring 14, Node 14, Django 14, Netty 3 → 5/2/6/1 NP+DI). **EPSS marginal-cost decomposition is still the right framing** and is now more prominent on the dashboard (commit `51acec3` D3 swapped the generic NP+DI insight tile for the "EPSS adds 1 marginal patch event over NP+DI+DQ at 0.50" copy). **Honest about confounders** (N=1 in-scope exploited in 12-month window, OS LPE keyword inflation) — both still on-page, both better-labeled now than 24 hours ago.

What's specifically improved on this pass:

- **DI CWE set is now frozen** (commit `06a7192` + `config.json:di_cwe_freeze`). 31 CWEs locked at 2026-05-01. Forward-validation counter live on the dashboard. This is the single most important credibility move the project has made — every reviewer concern about "you fit the filter to the data" is now answered by a public ledger that updates daily.
- **Live tracker (`docs/dashboard.html` lines 184–224) is wired into the refresh agent** via `scripts/refresh_post_apr1.py` (commit `1442ae3`). Self-contained refresher that re-pulls OSV per-package, computes 7-day clusters, and writes `data/post-apr1-per-framework.json`. The earlier risk that a "live" tracker would silently drift because the daily agent didn't touch its caches is now closed.
- **The live tracker has its own devil's-advocate callout** (line 220, "Other side of the argument") that pre-empts the "n=1 ActiveMQ + tier A in a round we already ran = circular" critique. That's the right voice for this work; the rest of the project should pull more of it.
- **Hero KPI swap** moved 251d→11d to the supporting-stats row and put 10/11 union with "91% effectiveness, 3.2× overhead per real exploit" in the load-bearing slot. Aligns the dashboard with the May-1 recommendation and with the document's actual claim.
- **Reading-time table on `index.html`** got the 60-second row plus extended verify-the-work links (CLASSIFIER.md, tests/run.sh) — also a May-1 ask, also landed.

### 1b. Where I'd push back, on this pass

**The freeze counter is currently 0/0/0/0/0/0 and it stays that way until enough post-freeze C/H events come through to populate it.** April 2026's 13 in-scope events are in the live tracker (line 778+, `POST_APR1.events`) but they're pre-freeze (April 1 to April 15; the freeze is May 1). The counter starts populating only when fresh post-May-1 C/H disclosures hit one of the 5 tracked manifests. Realistic cadence for this manifest is ~2–4 in-scope events per month. **Day-1 reality:** the counter shows zeros. **Recommendation:** add one sentence above the tile grid: *"The counter is initialized at zero; the live tracker below shows pre-freeze April events. The first post-freeze event will populate this band."* That converts the empty tiles from "is this thing wired up?" to "we just started."

Connected concern: **the freeze counter and the live tracker are computing on different windows.** The freeze counter is "events scored since 2026-05-01"; the live tracker is "events since 2026-04-01." That's a 30-day overlap where events appear in the tracker but not the counter. A reader will notice. **Recommendation:** label the tracker explicitly "April 1 → today (includes one month of pre-freeze events for context); freeze counter above starts May 1." One label, no data change.

**The live tracker's "Model" column conflates NP+DI ∪ Hacker S+A with the documented Union (NP+DI+DQ ∪ Hacker S+A).** The page comment at line 772–774 acknowledges this honestly: *"DQ requires per-event AI re-validation… for fresh events it's currently null."* That's defensible as an interim choice. But the dashboard's strategy-efficiency table just above (line 240+) still scores Union as "NP+DI+DQ ∪ Hacker S+A" with 91%. So the *table* and the *live tracker* score events differently and the reader has to read the comment in the JS to know. **Recommendation:** add a one-line caption under the live-tracker chart: *"This live tracker scores Union as NP+DI ∪ Hacker S+A (DQ pending per-event AI re-validation). The 91% / 10-of-11 efficiency above scores the canonical 7-year set with DQ folded in."* That closes the discrepancy without forcing a methodology change.

**The freeze policy says "if hacker S+A doesn't fire either, the event is recorded as a genuine miss."** That's the right policy. But **who scores the hacker tier on a fresh event?** The agent prompts in `agents/refresh-prompt.md` and `agents/analyst-prompt.md` should be updated to require a per-event hacker tier judgment for any new in-scope C/H event hitting a tracked manifest, with the result written back to the live-tracker's events array. If no agent is responsible, the counter will quietly under-fire (the analyst won't know to score new events) and the "missed" tile will fail to populate when a real miss happens. **Recommendation:** add a step to the analyst-agent's daily run that scores any new event with `hacker: null` in `data/post-apr1-per-framework.json`. The 5 events in the tracker today with `hacker: null` (the two `activemq-broker` / `activemq-client` CVE-2026-39304 rows and three uncovered Spring AI cluster rows) are concrete instances where this is owed.

**The DI CWE freeze rationale is principled but the "events seen since freeze" framing depends on a definition of "in-scope" that isn't in the freeze policy itself.** `config.json:di_cwe_freeze.policy` says "if a confirmed-exploited CVE has a CWE not in this list, it is NOT added — that would be hindsight goalpost-moving." Fine. But "confirmed-exploited" is a moving target — KEV-only? KEV ∪ MSF ∪ EDB? KEV ∪ MSF ∪ EDB ∪ Nuclei? The 7-year backtest uses KEV ∪ MSF ∪ EDB (per `data/foss-sub7-scoring.json` and `scripts/build_seven_year_npdi.py`). The post-freeze counter should use the same definition. **Recommendation:** add `di_cwe_freeze.exploited_definition: "KEV ∪ Metasploit ∪ ExploitDB"` and reference it in the dashboard caption — otherwise a reader can fairly ask "what counts as exploited for the missed tile?"

**Devil's advocate (user preference: think about the other side):** the freeze converts a methodological strength into a methodological constraint. Suppose six months from now a new exploit class emerges in NVD with CWE-1395 (or whatever — pick a CWE that doesn't currently exist). Several attackers hit it; it's clearly the same trust-boundary pattern as injection. Under the freeze, this CWE is *not* added to the DI set; the policy says hacker S+A is the rescue lane. **What if hacker S+A *systematically* misses this pattern** (because it's a structural new thing, not a tier judgment)? The freeze then becomes an albatross: the project committed publicly to not widening DI even in the face of empirical evidence the widening was correct. The defensible answer is that the freeze is a 6–12-month commitment with a planned post-period review, not a permanent lock. **Recommendation:** add `di_cwe_freeze.review_date: "2026-11-01"` (or similar 6-month horizon) and an explicit policy: *"Counter results trigger a published review — additions to DI may resume after the review with a documented rationale."* That preserves the falsifiability win while leaving the project room to learn.

**The "0/4 KEV-confirmed sub-7 entries clear hacker S+A" finding from the FOSS sub-7 page (in pass 8) deserves a louder cross-link from the canonical strategy efficiency table on the dashboard and `periodicity.html`.** It's the single best piece of evidence that the hacker rubric is *correctly conservative* on small-blast-radius bugs — it doesn't fire on commodity XSS or off-by-one DoS even when those bugs make it into KEV. Right now this finding lives only on `foss-sub7.html` (still labeled "scratch"). **Recommendation:** add a one-line callout on the dashboard "Three Response Lanes" or strategy-efficiency table: *"Sensitivity: at CVSS<7, hacker S+A correctly fires on 0/4 KEV-confirmed mediums — the rubric reserves S/A for actually scary stuff, not commodity XSS. See [foss-sub7](foss-sub7.html) for the data."*

### 1c. Does the OS chaining / kill chain framing still hold?

Yes, with no change since pass 8 (the cleaned-LPE numbers are now consistent across walkthrough §7, periodicity §"OS Layer", and dashboard "Three Response Lanes"). The **container-runtime watch list** recommendation from May-1 §1c is still open. The pass-7 `data/seven-year-per-framework.json` 30% per-framework catch rate is correctly handled now: the canonical 58-pkg manifest sits in `index.html` §4f and `periodicity.html` §"Real-World Manifest" with 10/11 union, while the 4×30% per-framework number is the workload-on-narrower-manifest stat that doesn't compete with the discrimination claim. No further surgery needed there.

### 1d. External validation

EPSS marginal-cost framing is now the dashboard's primary external-validation hook (commit `51acec3` D3). KEV / MSF / EDB / Nuclei correctly framed as low-power corroboration. The May-1 §1d framing holds.

One small additional note: **the watch-list KPI band's "5/19 promoted to KEV" is now stale.** Today's `kev-tracking.json` shows 6/20 watch-list entries confirmed in KEV (CVE-2024-1708, -39987, -32201, -34197, -34621, -33825), with 2 newly escalated to PoC status (CVE-2026-5194, CVE-2026-20180). The KPI band on the dashboard still reads 5/19. **Recommendation:** sync the KPI numerator/denominator to the latest tracking-json on the daily refresh path. This is a one-line script update for `scripts/refresh_post_apr1.py` or the dashboard's data-rebuild step.

---

## 2. Walkthrough restructuring recommendations (current state)

### 2a. Current outline (after May-1 chunk α)

`docs/index.html` headings as of HEAD:

1. The Problem (§1, h2 line 214)
2. The First Clue: Where Exploits Actually Land (§2, h2 line 237) — observational backbone
3. The Threat-Based Prioritization Model (§3, h2 line 337) — NP+DI + hacker
4. Does It Actually Work? Cross-Framework Validation (§4, h2 line 438) — 14-14-14 + 7yr backtest
5. Why Most Criticals Don't Get Exploited (§5, h2 line 590) — survivorship
6. Time-to-Exploit Compression (§6, h2 line 613)
7. Land & Expand (§7, h2 line 638) — kill chain
8. External Validation (§8, h2 line 683)
9. Operational Response by Estate Maturity (§9, h2 line 759) — Cat 1/2/3
10. The Reverse Proxy Myth (§10, h2 line 820)
11. Exploit Watch List (§11, h2 line 853)
12. Caveats (§12, h2 line 919)

This is the same ordering as May 1. The May-1 review's recommended reorder (move §5/§6 ahead of §3 as motivation; move §7 after §8 into the operational arc) has *not* been done.

### 2b. The reorder is still the highest-leverage editing pass available

Restating from May 1 because it still applies and is unambiguously the right next move:

The reader currently meets the validation (§4) before learning *why we expected the filter to work* (§5 survivorship: most C/H are sandboxed, behind auth, or don't reach attacker-relevant surfaces; §6 TTE: when something does get exploited it happens fast, so a slow process won't catch it). §5 and §6 are motivation for the model, not appendices to it. The fix:

**ACT 1 — The problem & motivation.** §1 problem, §2 observation, §5 survivorship, §6 TTE.
**ACT 2 — The model.** §3.
**ACT 3 — Does it work?** §4 cross-framework + 7-year, §8 external validation.
**ACT 4 — How to operate it.** §7 kill chain (justifies monthly container refresh), §9 estate maturity, §11 watch list, §10 reverse proxy myth (sidebar), §12 caveats.

This is a section-renumber + a 90-minute editing pass to retie cross-references. No new content. The May-1 review estimated this; nothing about that estimate has changed.

### 2c. New on this pass: §1.6 of the live-tracker work belongs in the walkthrough

The dashboard's live tracker (April 1, 2026 forward, with the freeze counter above it) is the most operationally compelling artifact on the site. The walkthrough currently has no equivalent — §4f is the 7-year backtest, §4 is the 12-month synthetic. Neither talks about the post-freeze prospective ledger. **Recommendation:** add a §4g (or §4.5) titled "What the filter is doing right now" with one paragraph describing the live tracker: 5 manifests, daily refresh, freeze counter, link to dashboard. Include the April 2026 worked example: 5 modeled rebuilds (1/1/1/0/1) vs 5 forced rebuilds under all-C/H — a narrow gap because April was busy, exactly the honest framing. Two paragraphs, link, done. The walkthrough currently *implies* there's a public ledger but doesn't show the reader where to find it.

### 2d. Smaller surgery still owed

- **`§3 (the model)` is still doing double duty** (NP+DI definition + hacker definition + DI CWE set + falsifiability). The May-1 split recommendation (3a/b structure, 3c falsifiability, 3d hacker, 3e motivation moved to ACT 1) is unchanged.
- **The "12-month zero misses" framing in `periodicity.html` lines 665 and 839** is now caveated nicely on `index.html` (§4f at line 690 and §12 at line 947 both spell out "operationally vacuous"). The same caveat needs to land on `periodicity.html` lines 665 and 839 — they currently read as headline claims without the N=1 disclosure. Two-sentence inline edit.
- **§7 (kill chain) figure** — May-1 noted the 21 LPE chart vs cleaned 10–12 prose mismatch. The dashboard "Three Response Lanes" was fixed in `dc4af0d` but the walkthrough §7 chart wasn't checked against this in pass 8. Worth a quick verification: are §7's LPE numbers cleaned-set or raw-keyword? If raw-keyword, swap.
- **CWE-set freeze acknowledgement on `index.html`** — the walkthrough's §3a still describes the DI CWE set as if it's evolving. Needs one sentence acknowledging the 2026-05-01 freeze and pointing to `config.json:di_cwe_freeze`. Lower priority (the policy is on the dashboard) but the walkthrough is the canonical narrative — readers who read only the walkthrough should know about the freeze.
- **The reading-time table now has the 60-second row** — confirmed live at line 180. A1 / A2 / A3 from May-1 are all landed. No further surgery needed.
- **The §11 watch list** is now 18 server-side + 2 desktop in `config.json` (per latest `kev-tracking.json`: 20 total, 6 confirmed). The walkthrough's §11 table needs to confirm the ConnectWise CVE-2024-1708 add (already in dashboard `WATCH_LIST.server`) is also present in the walkthrough's own §11 table. Quick verification owed.

### 2e. Should periodicity.html fold in?

Still no, same reasoning as May 1. The methodology page is ~1,100 lines; folding it into the walkthrough makes both unreadable. The cross-link strategy is correct. One incremental: the walkthrough's §4f currently duplicates the strategy-efficiency table that lives on periodicity.html §"Strategy efficiency". Either keep one canonical home (periodicity.html) and stub a 4-row summary on the walkthrough with a deep link, or accept the duplication and make sure both update together. Pass 8 §1.4-style duplication-of-numbers risk; not a blocker but worth picking a side.

---

## 3. Dashboard updates

### 3a. What the dashboard already has, that the May-1 review recommended

- **D1 — 7-year strategy efficiency table** is in. Lines 240–280. Six-row table, union row highlighted. Operational answer in the right slot.
- **D3 — EPSS marginal-cost stat** replaced the generic NP+DI insight tile.
- **D4 — Hero KPI swap** done. 10/11 union → top, 251d→11d → supporting row.
- **D5 — Days since CWE freeze** is the freeze counter now (lines 146–181).
- **(new since May-1) Live tracker** at lines 184–224, hooked into daily refresh agent.
- **A1 — Nav consistency** confirmed across 7 primary pages with `Mythos` as the standard label.

That's 5 of 5 May-1 dashboard recommendations landed in 24 hours. Material progress.

### 3b. What's still owed

1. **Pre-data caption on the freeze counter tile grid** (see §1b). The empty tiles need one sentence saying the counter is initialized and the first post-freeze in-scope event will populate it. ~30 minutes.
2. **Window-disclosure caption on the live tracker** (April 1 forward; freeze counter from May 1). One sentence, no data change. ~15 minutes.
3. **Live-tracker DQ disclosure** — note that Model = NP+DI ∪ Hacker S+A on this view, not the canonical NP+DI+DQ ∪ Hacker S+A. ~15 minutes.
4. **Watch-list KPI band sync** — 5/19 → 6/20, with 2 newly-escalated breakdown. Let the daily refresh path own this. ~30 minutes (one-line script update).
5. **Refresh agent / analyst agent prompt updates** to score hacker tier on new events (`hacker: null` → tier A/B/C/D/S) and to update the freeze counter tiles based on `data/post-apr1-per-framework.json` events with `disclosure_date >= 2026-05-01`. ~60–90 minutes; this is the biggest piece of remaining plumbing because it closes the "who fills the counter" loop.

### 3c. What's still vestigial on the dashboard

- The "What this filter doesn't cover" / blind-spots section is now at line 478, after the watch list. Better than before (it was higher up). Still slightly awkward immediately above the searchable KEV catalog. Tolerable. Lower priority.
- **CWE Families & Ransomware** chart (line 354) is observational; doesn't connect to a triage decision. May-1 §3c flagged this. Still vestigial. Lower priority.

---

## 4. Cross-page architecture

No changes since May 1's §4. The four primary pages (`index.html`, `dashboard.html`, `periodicity.html`, `cve-reference.html`) plus three secondaries (`glasswing.html`, `build-mechanics.html`, scratch pages) form the right set. The reading-time table on `index.html` is now doing its job at the front door.

The one new architectural observation: **the live tracker on the dashboard is more granular than anything on the walkthrough.** A reader who lands on the walkthrough will not know there's a daily-updating ledger of post-Apr-1 events with per-event NP+DI / hacker / exploited flags. The walkthrough §4 should at minimum have a "and here's the live ledger" link. See §2c.

The other architectural concern: **freeze counter + live tracker are logically related but visually separated.** On the dashboard they're two different cards (lines 146–181 and 184–224). They tell one story. **Recommendation:** consider visually grouping them under a single section title like "The Forward Validation Ledger" with two sub-cards — would make the reader's mental model match the conceptual model.

---

## 5. Devil's-advocate consolidated (user preference: think about the other side)

The May-1 review carried five hostile angles. Recapping where each stands today:

1. **"You fit the filter to the data."** Now answered structurally by the freeze. The counter on the dashboard is the public ledger; once it has 30+ events it converts the critique into evidence. Day 1 today.
2. **"Hacker S+A is unfalsifiable / no inter-rater reliability."** Still open. The hacker-tier rounds in `analyst-reports/2026-04-25-hacker-ranking-v2.md … v9.md` exist but no cross-rater stat has been published. Still owed.
3. **"Filter discrimination only proven on Java enterprise."** Partial answer landed: the FOSS sub-7 page tested across ecosystems at medium severity (87% catch). 7-year discrimination on Python/Node manifests still open work.
4. **"Burst pattern is overinterpreted."** Still open. Pass-7 / May-1 framing recommendation (drop "averages lie", show dates) hasn't landed.
5. **"Container-breakout is the worse chaining vector and isn't on the OS watch list."** Still open. May-1 recommended a fourth control (kernel/runtime watch list); not yet built.

New devil's-advocate points specific to this pass (the freeze + live tracker):

6. **The freeze date was set to 2026-05-01 (yesterday).** A hostile reviewer notices this is right after the May-1 review recommended the freeze. The freeze is therefore not an *independent* commitment — it's a recommendation the project acted on within 24 hours of receiving it. Not a problem but worth disclosing transparently. **Recommendation:** in `config.json:di_cwe_freeze.decision_rationale`, note that the freeze date was selected to coincide with the publication of the May-1 review's recommendation. Time-stamp transparency.
7. **The 31-CWE frozen set still includes 15 CWEs with zero observed exploitation in `data/di-cwe-backtest.json`** (CWE-95, -1336, -90, -776, -113, -23, -36, -98, -93, -96, -97, -1236 [if present], -289, -693, -1321 — pass-7 §1.1 list). These are in the set on patternist grounds. Freezing a set that contains a long tail of empirically-empty CWEs locks in a known weakness. **Counter-argument:** CWE-95 etc. are rare-but-attested injection patterns, and removing them at freeze-time would be its own form of post-hoc selection. Defensible to keep them. But the rationale for keeping them should be on-page, not just in the analyst's review file.
8. **The live tracker's headline (April 2026 worked example) catches the lone April KEV (CVE-2026-34197 ActiveMQ) on hacker tier A in a round we already ran.** That's one of the two cleanest possible critiques: tier A is partly a function of how thoroughly we've previously covered ActiveMQ, so the "discriminator firing" is partly retrospective. The dashboard's "Other side of the argument" callout already says this. Good. The walkthrough §4 doesn't yet — when §4g (per §2c) lands, it should pull this honest framing forward.

---

## 6. Daily scan addendum (2026-05-01 → 2026-05-02)

### 6a. KEV / new CVE activity

Per `kev-tracking.json` (today's 2026-05-02T04:15Z run, commit `ffcc165`):

- **KEV catalog 2026.05.01 → 1,587 entries** (+1 since 2026-04-30). New addition: **CVE-2026-31431 Linux Kernel** (CWE: Incorrect Resource Transfer Between Spheres). Not HTTP-parsing-adjacent; not on watch list; no NP+DI flag.
- **April 2026 KEV final = 31** (last addition was CVE-2026-41940 cPanel/WHM auth bypass on 2026-04-30; that one is HTTP-adjacent, CWE-class missing-auth, would clear NP+DI under the new auth-bypass widening — worth a follow-up).
- **NVD May MTD = 268** through day 2 (extrapolated 4,154 for full month — well below April's 5,885 final, but day 2 is too early to extrapolate).
- **Watch list status: 6/20 confirmed in KEV, 11/19 unconfirmed have PoC repos indexed in GitHub.** Two newly escalated to PoC: CVE-2026-5194 (wolfSSL cert validation, Claude-credited) and CVE-2026-20180 (Cisco ISE, OpenAI Codex-credited).

### 6b. Glasswing / Mythos news

- **No new Claude-credited CVEs since last refresh.** Glasswing total stays at 283 (Firefox 271, wolfSSL 9, F5 NGINX Plus 1, FreeBSD 1, OpenSSL 1). 6 Claude-credited CVEs unchanged.
- **MFSA 2026-35 (Firefox 150.0.1) and MFSA 2026-37 (Firefox ESR 115.35.1) reviewed**; no new explicitly-Claude-credited CVEs surfaced. Mythos coverage stable.
- **New AI-discovery non-Mythos signal:** **Wiz disclosed CVE-2026-3854 (GitHub Enterprise RCE)** found via "AI-augmented reverse engineering" using IDA MCP — *not* Mythos. The mythos-monitoring section flags this as a candidate for `glasswing_targets.ai_attributed_non_mythos_cves` pending more credit detail. **Recommendation for tomorrow's run:** check the Wiz blog post for explicit AI-tool attribution; if confirmed, add to `ai_attributed_non_mythos_cves` next to the Cisco-Codex cluster. The cross-vendor AI-discovery wave continues to broaden — IDA MCP, OpenAI Codex, and Mythos are now three distinct AI tools producing exploit-class CVEs in the same window.
- **csoonline.com headline:** "Behind the Mythos hype, Glasswing has just one confirmed CVE." That's the FreeBSD CVE-2026-4747 the press is consistently treating as the single "confirmed Mythos find." The 5 Firefox MFSA-2026-30 attributions and the Bouncy Castle CVE-2026-5588 are not yet getting picked up in the popular reporting as Glasswing finds. Worth a one-paragraph correction in `glasswing.html` if that page hasn't already addressed it: 6 Claude-credited CVEs is the count, not 1.

### 6c. Glasswing participant cross-check

Ran new May 1–2 CVE candidates against the participants list (`AWS`, `Anthropic`, `Apple`, `Broadcom`, `Cisco`, `CrowdStrike`, `Google`, `Intel`, `JPMorganChase`, `Linux Foundation`, `Microsoft`, `Nvidia`, `Palo Alto Networks`):

- **CVE-2026-31431 (Linux Kernel)** — `Linux Foundation` is a participant. Bug class is kernel (CWE class "Incorrect Resource Transfer Between Spheres" — privilege/sphere boundary), NOT HTTP-parsing-adjacent, so doesn't qualify under `probable_participant_cves` HTTP-adjacent criteria. Skip.
- **CVE-2026-3854 (GitHub Enterprise via Wiz/IDA-MCP)** — `Microsoft` (GitHub parent) is a participant. AI-discovered. But the AI tool is explicitly IDA MCP, not Mythos. Goes in `ai_attributed_non_mythos_cves`, not `probable_participant_cves`. **Recommended for tomorrow:** add Wiz-IDA-MCP entry to `ai_attributed_non_mythos_cves` mirroring the Cisco-Codex schema.
- **CVE-2026-41940 (cPanel/WHM)** — not a participant vendor.
- **Spring AI cluster (CVE-2026-40966 / -40967 / -40978 / -40979 / -40980)** — Spring is `Broadcom`-owned (via VMware). HTTP-adjacent. No third-party credit visible yet. Pass 8 §5b flagged this as a probable-participant signal worth watching but not yet adding. Today's tracking shows them on the watch list (status: watching). **Status unchanged:** still suspect, still not enough to add to `probable_participant_cves`. Recommend tomorrow's run check for Spring/Pivotal/Broadcom AI-tool attribution; if any explicit Mythos connection appears in vendor advisories, escalate.

### 6d. Today's tracker delta

- **Live tracker `data/post-apr1-per-framework.json` snapshot_through:** 2026-05-01. So as of today's run, the tracker is one day behind. The daily refresh agent (`scripts/refresh_post_apr1.py`) should advance it on its 5:03 AM run. Not a problem yet; flag if still 2026-05-01 tomorrow.
- **No post-freeze in-scope events yet.** Freeze counter remains 0/0/0/0/0/0 as expected.

### 6e. Two small items for the next refresh agent run

1. **Score the 5 `hacker: null` events in `data/post-apr1-per-framework.json`** (CVE-2026-39304 ActiveMQ pair — note: also need to check if these have been re-classified after disclosure, the broker/client pair sharing one CVE is unusual) — pass-8-style cleanup. The freeze policy needs every event to have a hacker tier so the rescue lane is properly scored.
2. **Sync the watch-list KPI band on the dashboard** with today's `kev-tracking.json`: 5/19 → 6/20, with the 2-PoC-escalation breakdown. The KPI band is the most prospective-validation visible artifact on the dashboard; keeping it stale undercuts the freeze ledger story.

---

## Closing note

The May-1 review's core asks were two: **freeze the DI CWE set with a public ledger, and reorder the walkthrough.** The first landed in 24 hours (with the live-tracker plumbing built around it). The second hasn't been done yet and remains the highest-leverage editing pass available. The freeze + live-tracker work is materially the strongest move the project has made — every reviewer concern about post-hoc fitting is now answered by a public counter. The remaining work splits into (a) finishing the agent prompts so the counter actually populates correctly, (b) the still-pending walkthrough reorder, and (c) closing the small captioning/disclosure asks on the dashboard so the empty tiles read as "this is initialized" rather than "this is broken."

Net direction: project is in a tightening cycle, not a restructuring cycle. The freeze converted the strongest standing critique into the strongest forward-validation surface; the next 30 days of post-freeze events are now the most informative signal the project will produce.
