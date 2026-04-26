# Cross-ecosystem efficiency test — Round 4 (Django/Python, N=181)

**Date:** 2026-04-25
**Question:** Does the 4-6x oracle efficiency claim from Round 3 hold outside the Spring/Java profile?
**Inputs:** `analyst-reports/2026-04-25-hacker-ranking-v4-django.md` (hacker tiering of 181-event Django manifest, blind), `data/_seven-year-frameworks-cache.json` (django manifest raw OSV)

## Headline

The hacker discriminator generalizes; NP+DI does not.

| Manifest | Events | Exploited | Hacker S+A standalone | NP+DI alone | NP+DI ∪ S+A |
|---|---|---|---|---|---|
| Spring/Java (R3) | 175 | 11 | 44 patches → **4.4x oracle** at 91% recall | 34 → **6.8x** at 45% | 60 → **5.45x** at 100% |
| Django/Python (R4) | 181 | 4 | 23 patches → **5.75x oracle** at 100% recall | 32 → **16.0x** at 50% | 44 → 11.0x at 100% |

Two takeaways:

1. **Hacker S+A is ecosystem-portable.** 4.4x → 5.75x is essentially noise — both within the 4-6x band the user's question was probing. The hacker reasoned the same way (default-config × network-edge × primitive-direct), found different shapes (no JVM deserialization, but Unicode-normalization auth bypass + image-library memory corruption + JWT alg-confusion + WSGI header smuggling), and the precision/recall trade held.

2. **NP+DI is roughly Spring-specific.** On Spring/Java it captures 5/11 = 45% of exploits at 6.8x oracle. On Django/Python it captures 2/4 = 50% at 16x oracle (much worse) — and adding NP+DI to hacker-S+A *hurts* efficiency from 5.75x to 11x because NP+DI flags 21 extra events not in hacker-A and catches zero additional exploits. NP+DI on Python is dragging down precision without adding recall.

## The 4 exploited Django events

| CVE | Package | CWE | Primitive | Hacker tier | NP+DI | Why |
|---|---|---|---|---|---|---|
| CVE-2018-7750 | paramiko | CWE-287 | Server-side SSH auth bypass | A | ✓ | NP+DI catches: paramiko is NP, CWE-287 widened DI |
| CVE-2019-19844 | django | CWE-640 | Unicode-normalization password reset hijack | A | ✗ | NP+DI misses: CWE-640 not in DI |
| CVE-2023-4863 | pillow | CWE-787 | libwebp Huffman OOB write (RCE shape via WebP upload) | A | ✗ | NP+DI misses: pillow not NP, CWE-787 not DI |
| CVE-2025-64459 | django | CWE-89 | ORM `_connector` kwarg SQLi | A | ✓ | NP+DI catches |

**All 4 in hacker-A.** The hacker's S-tier was empty (no event passed default-config × network-edge × primitive-direct unconditionally — Python's dangerous defaults have been mitigated harder than JVM's), but the 4 actual exploits are exactly the 4 events the hacker called "A leaning S — one deployment-shape question away from S." The hacker's discrimination is intact; the recalibration is that A becomes the actionable tier in Python (vs S in Java).

## Cross-ecosystem efficiency table

Patches per true positive (1.0x = perfect post-hoc oracle, lower is better):

| Policy | Spring/Java (R3) | Django/Python (R4) | Notes |
|---|---|---|---|
| Perfect oracle | 1.00x | 1.00x | post-hoc minimum |
| Hacker S only | 1.00x (5/5, 45% recall) | (empty) | S empty in Python |
| **Hacker S+A standalone** | **4.40x (91% recall)** | **5.75x (100% recall)** | **portable** |
| NP+DI only | 6.80x (45% recall) | 16.0x (50% recall) | **NOT portable** |
| NP+DI ∪ hacker-S | 5.14x (64% recall) | 16.0x (50% recall) | adds nothing on Python |
| NP+DI ∪ hacker-S+A | 5.45x (100% recall) | 11.0x (100% recall) | NP+DI drags precision down on Python |
| Patch all | 15.9x | 45.3x | upper bound |

## Why NP+DI fails on Python

The 2 events NP+DI misses on Django are exactly the "AI scan tier" gaps that periodicity.html has been describing all along:

- **CVE-2019-19844 (CWE-640 password reset)**. The DI set doesn't include CWE-640 (weak credential recovery) by design — it's not an injection-class bug. But the *primitive* is direct full auth bypass via Unicode-normalization confusion in the email lookup. The hacker explicitly said: "labeled CWE-640 'weak password recovery.' Sounds boring; *primitive is a unicode-normalization auth bypass that hands you a reset token to an account you don't own.*"
- **CVE-2023-4863 (libwebp memory corruption via Pillow)**. CWE-787 (out-of-bounds write) is not in DI — it's memory-safety, not injection. And pillow-the-package is util-coded as role=OTHER, not NP. The hacker said: "the actual bug is in libwebp's Huffman table builder, shared with browsers/Electron/many apps. The exploit shape is well-characterized at the libwebp layer... any avatar/profile-image upload path is a delivery vehicle."

Both are events where the hacker reasoned from the actual primitive shape rather than from CWE/package classification, and got the right answer. NP+DI as currently designed cannot catch these without expanding either:

1. The DI set to include CWE-640 (Unicode/canonicalization auth bypass) and CWE-787 (memory corruption in network-edge parsers), OR
2. The NP set to include image libraries reachable via avatar/profile-upload endpoints.

Both would over-broaden the filter on Spring/Java where those CWEs/packages don't predict exploitation as cleanly. The hacker's three-axis discriminator handles this naturally because it doesn't reason from CWE — it reasons from primitive shape × edge reachability × default-config.

## Why hacker-S+A generalizes

Looking at the four exploits on Django, each one matches a different Python-native primitive class the hacker explicitly called out:

1. **Unicode-normalization auth bypass** (CVE-2019-19844): pure Python framework foot-gun, no JVM equivalent.
2. **Server-side auth bypass in protocol-handling library** (CVE-2018-7750): paramiko-as-server is the Python analogue of Spring SecurityContext bugs from rounds 2-3.
3. **Library-layer memory corruption with weaponization recipe** (CVE-2023-4863): the libwebp bug shared with browsers — the only Pillow heap-corruption with a credible exploit pathway.
4. **ORM internal-API SQLi** (CVE-2025-64459): the cleanest Django ORM primitive to actually reach.

The hacker A-tiered all four because each one passed two of the three axes (network-edge + primitive-direct) and fell short of S only on default-config (each is one app-shape question away). On Spring, equivalent two-axis events were uniformly A-tier in R3 too — the difference is that Spring/Java has a populated S-tier (Log4j, ActiveMQ, deser-RCE chains) where Python doesn't. Same discriminator, different conditional-probability profile.

## Why is Python's S-tier empty?

The hacker articulated this directly: "Python's fastest one-shot-RCE primitive (`pickle.load` on untrusted bytes) was killed at the library default. numpy made it opt-in, the broader ecosystem learned the lesson. The Spring/Java equivalent (deserialization gadget chains) was *not* killed at the default — Spring/Tomcat keep shipping ObjectInputStream-on-the-wire patterns. So the Python ecosystem genuinely has fewer one-shot-RCE primitives by default."

Three contributors:
1. **Real signal**: Python ecosystem hardened its dangerous defaults (`pickle.load`, `eval()` in templates) more aggressively than JVM enterprise.
2. **Selection effect**: this manifest is missing Werkzeug debug-PIN, PyYAML loader, pickle-RPC servers, Flask routing-bugs — the Python attack-surface S-tier candidates that DO exist in the wild.
3. **Discriminator works correctly**: it identifies that nothing here is unconditionally one-shot, and that the actionable tier is A (deployment-shape gated) rather than S (default-config win).

## Implications for the triage policy

**Don't use NP+DI on non-Spring estates.** It was tuned on Java enterprise patterns and the over-fit shows. On a Python-shop estate, NP+DI alone is actively misleading: 50% recall at 16x oracle is worse than random within C+H (which would be 45.3x but at 100% recall — and NP+DI doesn't give you 100% recall).

**Hacker-S+A as a standalone classifier is the portable policy.** 4.4x at 91% recall on Java, 5.75x at 100% recall on Python. The mechanism (operator reasoning from primitive × edge × default-config) is ecosystem-agnostic; the resulting picks are ecosystem-shaped.

**Operationalize the hacker's discriminator, don't run an LLM hacker per quarter.** The output of these four rounds is a structured discriminator:

- Direct primitive: one-shot RCE, full auth bypass, full token forgery, server-process compromise — yes for S/A. Chain-into / DoS / info-leak / weak crypto config — no.
- Network-edge: vulnerable code path runs on attacker-reachable input from outside the perimeter.
- Default-config: vulnerable code path executes without admin opt-in, OR is a near-universal deployment pattern (avatar uploads, JWT-protected APIs, SSO-trust headers).

These can be encoded as boolean checks per event. The CWE-co-tag rule the hacker independently articulated also serves as a programmatic shortcut: "deser-class CVE co-tagged with CWE-306/862/285/287 → S; CWE-269/CWE-20/CWE-44 on a network-edge package → re-review for misclassification."

## Counter-argument worth holding

Three honest pushbacks:

**1. N=4 exploited on Django is a small sample.** Spring's 11 exploited gives more confidence in the precision/recall numbers than Django's 4. The 100% recall claim on Django is "hacker A-tier flagged 4 of 4" — flip one and you're at 75%. The directional finding (hacker generalizes, NP+DI doesn't) holds at any flip, but the precise overhead numbers are wide.

**2. Right-censoring is more severe on Python.** Two of the four Django exploits are recent (2023, 2025). The dataset has had less time to accumulate exploitation evidence on Python than on Java (where many of the bugs are 2018-2022). If the actual Python exploitation rate over the full 7-year window is higher than 4/181 = 2.2%, the precision numbers shift, but the hacker's standalone advantage over NP+DI likely widens (more A-tier events that actually exploit means hacker precision improves while NP+DI continues to miss memory-corruption / canonicalization-auth shapes).

**3. The empty hacker S on Python may itself be over-fit.** The discriminator was tuned on JVM where S = "default-config × network-edge × primitive-direct." Python may legitimately have S-tier events that the discriminator can't see because Python's S-tier shape is "framework-default unicode normalization treats lookalike characters as equivalent" rather than "default config trips a wire-format parser." A more ecosystem-aware discriminator might S-tier CVE-2019-19844 directly. Right now the discriminator handles it as A (correctly identifying the deployment gating) and gets the right answer through coverage rather than rank — which is operationally fine but theoretically less crisp.

## Net answer to the user's question

**The 4-6x efficiency claim holds outside Spring/Java for the hacker-S+A policy** (4.4x → 5.75x). It does NOT hold for NP+DI alone, which jumps from 6.8x to 16x and misses 50% of Python exploits.

The actionable read: **abandon NP+DI as a standalone filter on non-Spring estates**; use hacker-S+A reasoning (or its programmatic encoding) as the cross-ecosystem triage policy. NP+DI remains useful as a Java-specific accelerator but its generalization beyond JVM is poor.
