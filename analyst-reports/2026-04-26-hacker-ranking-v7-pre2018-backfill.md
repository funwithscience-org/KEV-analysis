# Hacker round 7 — pre-2018 backfill (3 events)

**Date:** 2026-04-26
**Why:** R3 input window was 2018-10-16 → 2026-04-15, so the three pre-2018 exploited events on the production manifest 7-year backtest (CVE-2013-7285 XStream, CVE-2017-12615 + CVE-2017-12617 Tomcat HTTP PUT) were marked "n/a" on the per-event detail table. They should be ranked under the same discriminator so the comparison is honest.

## CVE-2013-7285 — XStream OS command injection via XML

**Discriminator:** Default-config × network-edge × primitive-direct.
- **Default-config:** XStream pre-1.4.18 (which shipped in 2021) is **unsafe by default** — no `enableDefaultTyping`-equivalent needed; the default class loader will instantiate any tag the attacker names. 2013-7285 is well within the unsafe-default era.
- **Network-edge:** Per-app — gates on whether the app deserializes attacker-controlled XML. Many Spring apps in 2013-2018 era did exactly this for REST APIs, OXM mappers, configuration loaders.
- **Primitive-direct:** Deserialize → arbitrary command execution via XStream's default constructor injection. No chain-into needed.

**WAF status:** WAF-MEDIUM (XML class names signature-able but XStream gadget zoo wider than Jackson's).

**Tier:** **A.** Same baseline as the rest of the XStream pre-1.4.18 cluster R3 catalogued ("A as cluster, S for CVE-2021-39144 because of the CWE-306 missing-auth co-tag"). 2013-7285 doesn't have CWE-306 tagged, so it sits at A rather than promoting to S.

## CVE-2017-12615 — Tomcat HTTP PUT JSP upload

**Discriminator:**
- **Default-config:** **No.** Requires `readonly=false` on the default servlet — Tomcat's default is `readonly=true`. Some embedded Tomcat dev images and historic Tomcat configs flipped this, but standard Tomcat does not. Loses the default-config axis.
- **Network-edge:** Yes when reachable.
- **Primitive-direct:** Yes — PUT a JSP file, GET it back to execute. Two-request but unconditional once the precondition holds.

**WAF status:** WAF-FRIENDLY (PUT method + .jsp upload patterns are CRS-1 signature territory; emergency rule ships same-day).

**Tier:** **B.** Narrow-precondition rule. Strong primitive when the config is wrong, but not default. Not promoted to A because the discriminator's default-config axis is doing real work here — most Tomcat deployments are not vulnerable.

## CVE-2017-12617 — Tomcat HTTP PUT (Windows variant)

**Discriminator:** Same shape as -12615, plus Windows-specific case-insensitive bypass extending the precondition slightly. Still gated on `readonly=false`.

**WAF status:** WAF-FRIENDLY (same as above).

**Tier:** **B.** Same reasoning as -12615.

## Impact on the 7-year scorecard

Adding these three tier assignments to the per-event detail table:

| Metric | Was (with 3× n/a) | Now (with R7 backfill) |
|---|---|---|
| Hacker S+A direct catches | 9/13 (69%) | **10/13 (77%)** |
| Effective coverage with floor sweep | 11/13 (85%) | **11/13 (85%)** (no change — the file-upload pair stays missed; 2013-7285 was already covered by floor sweep through the XStream-39144 rebuild in 2021-Q3) |
| Hacker S+A patch events (7yr clustered) | 17 | **17** (CVE-2013-7285 patch event already counted in the XStream cluster — 2013-2018 saw multiple XStream patches and the trigger-date is unchanged) |
| Per-exploit overhead (efficiency) | 17 / 9 = 1.9x | **17 / 10 = 1.7x** |
| Union (NP+DI ∪ Hacker S+A) direct | 11/13 (85%) | **11/13 (85%)** (NP+DI catches 2013-7285 via NP+DI raw — both now agree on it; comparator already had it as a catch) |

The two structural unfixable events (CVE-2017-12615 and -12617, file uploads) remain the only events neither strategy reaches by either direct catch or floor sweep — that finding is unchanged.
