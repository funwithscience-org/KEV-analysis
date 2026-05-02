# Hacker S+A Inter-Rater Reliability — Methodology

**Status (2026-05-02): designed, not yet executed.** This doc is the
specification for the inter-rater study. The study itself fires when
we have a second rater available (a human analyst, or a different LLM
session blinded to the first rater's output).

## Why this matters

The integrated page leans on "hacker S+A" as the rescue path for any
event the NP+DI structure test misses. Per the freeze policy, the
hacker discriminator is now the only widening lever — the DI CWE set
is locked. So if hacker S+A is **operator-dependent** rather than an
intersubjective signal, the model rests on a single judgement, which
is exactly the critique the freeze counter was built to disprove.

The 7-year backtest scores hacker S+A at 9/11 catch (82%) at 1.2×
overhead. Those numbers come from R3-R8 ranking rounds, all done by
the same rater (Claude with the standard rubric). We have not yet
shown that an independent rater applying the same rubric to the same
event set converges on the same S+A bucket. Inter-rater agreement
above κ ≥ 0.6 ("substantial") would convert "this LLM agrees with
itself" into "the rubric is repeatable." Below κ ≥ 0.4 ("moderate")
would mean we should treat hacker tier as advisory, not load-bearing.

## Rubric (the thing being measured)

The hacker discriminator is a three-axis grade per CVE plus an
auth-missing co-tag, collapsed into a tier letter:

- **Default-config**: Does the bug fire with vendor defaults, or
  does it require an unusual configuration the customer chose?
  - Yes (default-config) → favors S/A
  - Requires unusual config → favors C/D
- **Network-edge**: Is the affected component reachable on the
  network edge (HTTP-facing, internet-reachable proxy, etc.) or
  only as a deep-internal service?
  - Edge-reachable → favors S/A
  - Internal-only → favors B/C/D
- **Primitive-direct**: Does exploitation give the attacker a direct
  primitive (RCE, auth bypass, sensitive data read) or only a
  building block that needs further chaining?
  - Direct primitive → favors S/A
  - Requires chaining → favors B/C/D
- **Auth-missing co-tag**: Set when no upstream authentication
  protects the path. Does not by itself promote a tier; it amplifies
  the network-edge axis.

Tier collapse:
- **S** — all three axes fire AND auth-missing
- **A** — all three axes fire OR (two fire AND auth-missing)
- **B** — two axes fire
- **C** — one axis fires
- **D** — none fire (or all axes are weak)

## Study design

### Sample frame

The R3 Java/Spring round of 175 events. Picked because (a) it's the
biggest single round we've published, (b) it has independent ground
truth (KEV/Metasploit/ExploitDB exploitation labels we can score
against), and (c) all events are public CVEs the second rater can
look up unaided.

Sample size: **all 175 events**, not a subset. Subsample would
under-power the kappa CI.

### Rater protocol

Two raters, each working independently. Each receives:

1. The blinded R3 input (`data/_hacker-input-blind-v3.json`) — CVE
   ID, package, severity, CWEs, affected versions, summary text.
   Crucially: **no exploitation labels, no prior tier judgement, no
   round-of-origin metadata**.
2. A clean copy of this methodology document (everything in this
   file above the "Study design" section).
3. The R3 retrospective advice document
   (`analyst-reports/2026-04-25-r3-retrospective.md`) — this gives
   both raters the same training prior, so any disagreement isolates
   judgement variance rather than calibration drift.

Raters write tier letter S/A/B/C/D + a one-line rationale per CVE.
Output schema mirrors `data/hacker-tiers.json`:

```json
{ "CVE-XXXX-YYYY": { "tier": "A", "rationale": "..." } }
```

Raters do NOT communicate during scoring. Each writes to a separate
file (`hacker-tiers-rater-A.json`, `hacker-tiers-rater-B.json`).

### Disagreement-resolution session

After both raters finish, a third pass (joint adjudication, both
raters present, transcribed) re-scores the disagreements. The output
of this session is the **canonical** post-IRR `data/hacker-tiers.json`
(or rather, the version that supersedes today's). The session
produces a third file: `analyst-reports/YYYY-MM-DD-hacker-irr-adjudication.md`
documenting the rationale for each post-disagreement decision.

This adjudication step is what makes the IRR study useful as more
than a self-validation exercise — every disagreement becomes a
sharpening of the rubric.

## Metrics

### Cohen's kappa on the binary S+A vs B+C+D dichotomy

The operationally-load-bearing distinction. The model fires on S+A
(triggers a rebuild) and ignores B+C+D (lets them ride normal cadence).
Inter-rater agreement on this dichotomy is what matters.

```
κ = (p_o - p_e) / (1 - p_e)

p_o = observed agreement on S+A vs other
p_e = chance-expected agreement
```

Target: **κ ≥ 0.6** ("substantial agreement"). Below 0.4 → rubric is
not load-bearable; above 0.8 → rubric is essentially deterministic.

### Weighted kappa on the full 5-tier scale

Captures whether disagreements are "off by one tier" (forgivable) vs
"S vs C" (catastrophic). Weights: linear (an S↔C disagreement
counts as 2 disagreements; S↔B counts as 1).

Target: **κ_w ≥ 0.5**.

### Per-axis agreement breakdown

For each of the three axes (default-config / network-edge /
primitive-direct), what fraction of CVEs do both raters agree on?
Identifies which axis is the noise source.

### Adjudication burden

Number of CVEs in the disagreement-resolution session vs total
sample. Above ~20% → rubric needs sharpening before re-running the
study; below ~10% → rubric is clear and the load-bearing claim
holds.

## Threats to validity

- **Same-foundation-model bias.** Both raters being LLMs of the same
  family (or both human, of similar background) inflate agreement
  without proving anything about the rubric. The strongest study
  pair is one human security analyst + one LLM rater. If we have
  only LLMs available, use models from different foundation families
  (e.g., Claude + GPT) and report kappa with the caveat.
- **Recall poisoning.** If either rater remembers seeing a CVE
  before in any context — KEV catalog, news, prior security work —
  they may import exploitation knowledge into their tier assignment.
  This biases agreement toward exploitation outcome, which is
  exactly what we want to test the rubric against. Mitigation:
  raters disclose any recognized CVEs at scoring time; those events
  are flagged in the kappa calculation but kept in the dataset (a
  separate sub-kappa for "novel-to-rater" events is the more useful
  number).
- **Rubric drift.** If we update the rubric between today and the
  study date, this doc should be re-versioned and the score baseline
  reset. The DI CWE freeze is a precedent: a public, dated lock.
- **Sample frame bias.** R3 is Java-only. Inter-rater on Java tells
  us whether two raters agree on Java events; it does NOT
  generalize to Node/Python/Go ecosystems. Repeat for at least one
  other manifest (Django R4 is the obvious next round) before
  claiming the rubric is ecosystem-portable.

## Reporting template

The study writes one report:

```
analyst-reports/YYYY-MM-DD-hacker-inter-rater-reliability.md

# Hacker S+A Inter-Rater Reliability — Round YYYY-MM-DD
## Sample
N=175 (R3 Java/Spring), pre-adjudication
## Headline numbers
- κ (S+A vs other): X.XX (95% CI [X.XX, X.XX])
- κ_w (5-tier linear): X.XX
- Adjudication burden: NN of 175 events (NN%)
## Per-axis agreement
- Default-config: NN%
- Network-edge: NN%
- Primitive-direct: NN%
## Notable disagreements (top 10)
... narrative table with CVE, rater A, rater B, adjudicated, why ...
## Implications for the published 9/11 hacker S+A backtest
... how many of the 7-year canonical 11 events shift tier post-adjudication ...
## Recommended actions
... rubric edits if adjudication burden >20%, training updates, etc.
```

## Hosting / public surface

When the study completes, the report goes on the dashboard alongside
the freeze counter as a sibling card: "Inter-rater reliability — κ =
X.XX, last measured YYYY-MM-DD." Below the threshold (κ < 0.4), the
hacker discriminator gets demoted to advisory in the Model definition
and the union shrinks to NP+DI+DQ alone — that's the contingency the
methodology has to honestly disclose.

## What's NOT included

- Triple-rater designs (Fleiss kappa). Two raters is enough for the
  load-bearing claim; three or more is for academic rigor we don't
  yet need.
- Cost/time-of-rating measurement. We're testing whether the
  judgement is repeatable, not whether it's cheap.
- Inter-temporal stability (same rater, T0 vs T1). That's a separate
  study (test-retest reliability), useful but lower priority than
  inter-rater.

---

Last updated: 2026-05-02. Spec only — study not yet executed. When
the first study runs, append a "Round YYYY-MM-DD results" section
below this line and update the dashboard sibling card.
