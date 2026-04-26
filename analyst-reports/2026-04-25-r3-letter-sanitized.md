# Operator Heuristics — Lessons Digest (Sanitized)

**Framing.** A prior operator ranked a 175-event manifest blind, was shown the answer key, and wrote a letter of advice. This is the sanitized version: the abstracted heuristics with all CVE-specific answer-key information removed. Use these as priors when ranking a new manifest. The lessons travel; the specific bugs that taught them do not appear here.

---

## 1. The discriminator works — keep it

**Default-config × network-edge × direct-primitive.** Three gates open = S. Two gates open = A. Anything else = B or worse.

The reason it works at small N: all three gates are *binary properties of the bug, not statistical properties of the deployment population*. You're filtering for bugs where the operator doesn't *need* to predict which targets will be vulnerable, because the bug itself eliminates the conditional.

- "Default-config" = no admin opt-in needed; the dangerous code path runs on a stock install.
- "Network-edge" = attacker-controlled bytes reach the vulnerable function from outside the perimeter.
- "Direct primitive" = one-shot RCE / full auth bypass / full token forgery, not a chain-into.

The gate test compresses three independent questions into one tier label. The compression is the value. Don't lose it chasing nuance.

**Use it. Don't replace it. Refine on the margins.**

---

## 2. The "narrow precondition" downgrade reflex is wrong

The instinct: "this bug only affects platform X with config Y enabled — niche, demote." That instinct is correct in expectation and wrong in fact.

The exploit-dev community will weaponize a sharp primitive with a narrow surface as long as the primitive is sharp enough. Module-write cost is a one-time investment that amortizes over weird fleets that exist (legacy intranet, vendor appliances, partial deployments, development environments left in production). The world contains weird fleets.

**Rule:** if a bug passes "default × edge × direct" *within its precondition stack*, tier it A regardless of how narrow the stack is. Treat the precondition as a "discovery cost" line item, not a "kill the tier" line item.

Three patterns the reflex tends to mis-handle:
- Platform-specific OS-injection bugs (Windows-only, *nix-only)
- Authentication-mode-specific bugs (mTLS-only, OAuth2-specific sub-modules, SAML-only)
- Framework-variant-specific bugs (WebFlux-only when MVC-default; specific deployment shapes)

Resist the demote. Bug shape sets tier; deployment count sets effort allocation downstream.

---

## 3. Patterns to actively skip

Categories that consistently absorb attention budget and yield zero exploitation evidence:

**The DoS bracket.** CWE-400 (resource exhaustion), CWE-770 (allocation), CWE-674 (recursion), CWE-835 (infinite loop), CWE-1333 (ReDoS). Universal D. Defender problem, not operator opportunity. Beware of CWE-502 co-tagged with CWE-400 on parser libraries — the CWE-502 reads like deserialization-RCE, but the co-tag with CWE-400 is the tell that the realistic primitive is "make the parser blow up" rather than RCE. Read the summary; if there's no "RCE / code execution / arbitrary code" language, it's a DoS impostor.

**Authorization-bypass clusters in security-decision libraries.** When a security framework ships ten CVEs across years for "authorization rule misconfiguration / matcher mismatch / forwarding bypass," each is real but each is *application-conditional*, not library-conditional. The framework ships safe defaults; the bug surfaces only when the app uses the specific feature in the specific wrong way. That makes generic exploit-modules expensive to write — operators route around. Tier A on CWE merit when the call is unambiguous, but don't burn campaign budget building modules for the cluster. They're audit findings, not exploit modules.

**Open redirects, RFD, header-missing, defense-in-depth weakening.** CWE-601, CWE-425, CWE-1188, hostname-verification bugs in client libraries. Universal C-or-D regardless of severity score. Severity over-sells every one of them. CWE-425 ("Direct Request Forgery") is the worst-named — sounds like SSRF, is actually about missing security headers.

**Local privilege escalation in a server-side library.** Tmp-dir hijacks, file-permission bugs, build-host LPE. Not a remote primitive. D for a remote operator.

**MITM-requiring bugs.** Hostname-verification, certificate-validation in client libraries. C at best — needs on-path position the operator either has or doesn't.

---

## 4. Patterns to actively LOOK for — generic CWEs hide sharp primitives

The CWE label lies, often in the same direction. Three high-yield patterns where the tag understates the realistic primitive:

**CWE-269 ("Improper Privilege Management") on a network-edge package.** Reads like a local LPE. When the package is a network server (HTTP daemon, message broker, gateway, protocol handler), the realistic primitive is often network-side: arbitrary file read, protocol-handler abuse, or chained RCE. The tag is wrong-by-genre. **Heuristic:** when CWE-269 appears on a network-edge package, assume the label is a category-error and read the summary for a network primitive.

**CWE-20 ("Improper Input Validation") on anything critical.** This is the laziest CWE in the entire system. It absorbs bugs across every primitive class — code injection, deserialization, auth bypass, command injection, anything where "the input was bad." On a critical-severity bug, CWE-20 means "read the summary; the real primitive is hiding." If the package is a network server or a security-decision component, default-assume the primitive is sharper than the tag suggests.

**CWE-44 / CWE-22 / path-class CWEs co-tagged with CWE-502.** The path tag alone reads like file-disclosure; the deserialization co-tag is the tell that the realistic exploit is a chained primitive — write a file with an embedded gadget, then trigger deserialization on that file. Promote one tier above what the path tag alone would suggest.

**The auth-missing co-tag rule** (the single most actionable heuristic). Any RCE-class, deserialization-class, or code-injection-class CVE co-tagged with CWE-306, CWE-862, CWE-285, or CWE-287 is more dangerous than the same primitive without the auth-missing co-tag. The auth-missing label is what turns "sometimes-reachable" into "always-reachable."

**Practical scan rule:** when triaging a fresh manifest, search the full CVE detail (not just the headline CWE) for CWE-306 | CWE-862 | CWE-285 | CWE-287 co-occurring with any RCE/deser/code-injection CWE. Treat every hit as a presumptive S until disproven.

---

## 5. The WAF axis — when it matters

A separate experiment added WAF-defensibility as an explicit fourth axis (was the bug WAF-friendly, WAF-medium, or WAF-hostile?). Adding it as a tier-discriminator did not improve precision/recall at the S+A union level. The new explicit promotions to S based on "looks legitimate to WAF" generated more false positives than true positives.

**Read:** WAF-hostility is not an independent axis at the dataset sizes we tested. It's already implicit in the existing axes — a non-HTTP-protocol bug is WAF-hostile precisely because of the network-edge characteristic; a famous logging-string bug is exploited despite WAF coverage because the attack volume outpaces rule deployment.

But the post-hoc cross-tab said: conditional on hacker-A, WAF-hostile bugs were exploited at ~1.8x the rate of WAF-friendly bugs. So the axis is real signal — just not as a tier promoter.

**Recommendations for the next operator:**
- Use WAF-hostility as a **tie-breaker within A**, not a promoter to S.
- Do **not** demote a known-S primitive based on "WAF rules will deploy fast" — that reasoning has failed empirically (see point 7 below).
- The genuinely useful application: **double-miss detection on the rejected pile.** Among bugs your filter rejects, those that are also WAF-hostile are the structural blind spot — neither layer catches them. Run WAF-hostility as a secondary check on the rejected set.

---

## 6. Cross-ecosystem cautions — when the manifest isn't JVM

The discriminator was tuned on JVM. A subsequent run on a Python web manifest produced **empty S-tier** — no event passed default × edge × direct cleanly. This is a valid outcome. Python's most dangerous one-shot primitives (the obvious deserialization paths) were killed at library defaults; the framework community ran a tighter ship on dangerous defaults than the JVM enterprise community did from 2017-2024.

**If you're handed a non-JVM manifest, recalibrate:**

- **Don't expect S-tier to fire.** Empty S is valid. The discriminator may produce S=0 on Python, Node, Go, Rust manifests because the language doesn't have the unconditional-deser shape. Don't force-promote to S to fill the bucket.

- **Promote auth-boundary input-normalization bugs.** Unicode case-folding, header normalization, JWT algorithm confusion, OAuth state validation, password reset token comparison, email canonicalization. These are A-tier in any language and may be the *highest* tier you get on non-JVM. The CWE labels for these (CWE-640, CWE-290, CWE-345) often understate.

- **Promote native-code parser libraries.** Image codecs, XML parsers, font parsers, video codecs. Memory-corruption primitives in network-reachable parsers ship with the JVM-equivalent of "default × edge × direct" — they just don't get tagged that way. The exploit-feasibility caveat: most heap-corruption in modern hardened binaries is a 95%+ crash primitive, NOT reliable RCE. The exception is bugs in shared underlying-C libraries (used by browsers, electron apps, many native consumers) where weaponization recipes have been worked out at the library layer rather than the wrapper layer. When the OSV/NVD detail says the bug is in an underlying-C library shared with browsers/Electron, promote.

- **JWT and crypto verification libraries are NP across ecosystems.** Always. The trust-boundary rule applies — JWT libs in any language, crypto libs that verify signatures/certs/tokens on attacker-supplied input. Tier with the auth-bypass cluster.

- **WSGI / ASGI / Rack header handling is the Python/Ruby equivalent of HTTP-server request-line parsing.** Smuggling, normalization, and header-injection bugs there should be A even when CWE labels are generic.

- **ORM-level SQLi exists and bypasses the "we use the ORM" defense.** Same shape as driver-level SQLi in JDBC drivers. Search for it in the ORM-cluster CVEs — the few that hit common application patterns (sortable list views, dynamic filter builders, column-alias generation) are A; the cluster baseline is C.

JVM-trained instinct undervalues: image-library memory corruption with weaponization recipes, Unicode normalization, JWT algorithm confusion, ORM-level SQLi. Adjust upward on those.

---

## 7. The "famous-bug patch coverage" trap

Reasoning that sounds plausible: "by the time the patch-bypass for a famous bug exists, perimeter WAF rules are already deployed; the reachable population is shrunk; demote." This reasoning has failed empirically.

Why it fails: the operator does not get only one shot at a fully-patched, fully-WAFed target. There is a long tail of unpatched, partially-patched, and stuck-on-the-bad-intermediate-version installs for every famous bug. The bypass-patch becomes the *more* useful exploit because it covers the cases where the operator has hit version-1-of-the-fix and bounced. Same payload class, complementary version coverage.

**Rule:** *Trust the bug class, not the patch number.* If the original is S, the patch-bypass is also S. The CWE shape is unchanged, the primitive is unchanged, the network reach is unchanged. Only the version range changes — that's a discovery question, not a tier question.

This applies broadly: any famous-bug-class follow-on patch, any "incomplete fix for prior CVE," any patch-bypass cycle on the same primitive. Bug class tiers; patch number doesn't.

---

## 8. Cluster handling — generic guidance

**Big polymorphic-deserialization clusters** (Jackson-style) — group as one tier with outliers. The cluster default is B because most members need the same opt-in configuration to fire (default-typing on, unsafe TypeInfo). Promote to A: the subset reachable WITHOUT the opt-in (rare). Demote to D: the DoS impostors co-tagged with CWE-400.

**Big XML-deserialization clusters** (XStream-style) — similar shape. Cluster default is A or B depending on whether the underlying library was unsafe-by-default in the affected versions. Promote to S: any single member co-tagged with auth-missing CWE (CWE-306).

**ORM SQLi clusters** — cluster default is C because most members require atypical ORM API usage. Promote to A: the few that hit common application patterns (sortable views, dynamic kwargs, column aliases). The letter author was wrong to dismiss these in early rounds; some ARE exploited, just the right subset.

**Image library clusters** — most heap-corruption is C/D for production weaponization (95%+ crash, low reliability). Exceptions promote to A: eval-class injection bugs (which are not memory corruption); bugs in shared underlying-C libraries with known weaponization shapes.

**Tomcat / app-server-internal clusters** — tier individually. Bug-by-bug, the difference between a deserialization-RCE and a request-smuggling and a DoS is large enough that cluster-default makes no sense.

---

## 9. Two failure modes worth naming

Both came from real ranking errors in the prior rounds, abstracted here:

1. **Demoting on narrow precondition.** The reflex says "minority deployment, demote." The world contains weird fleets. Bug shape sets tier; precondition sets effort.
2. **Demoting on famous-bug WAF coverage.** The reflex says "WAF rules will catch it before the patch ships." The long tail of unpatched intermediate-version installs is what gets hit. Trust the bug class, not the patch number.

These are the two specific failure modes the prior operator and a follow-up WAF-aware operator hit. Avoid them.

---

## 10. Closing

The discriminator is the asset. Don't break it trying to fix the edges. The edges fix themselves on a per-engagement basis: discovery cost and target distribution are what you tune for *after* the tier list, not what you encode *into* the tier list.

Hold the line on default × edge × direct. Promote auth-missing co-tags aggressively. Read the summaries, distrust generic CWEs (especially CWE-20 on critical, CWE-269 on network-edge, CWE-44+CWE-502 chained). Don't downgrade narrow-precondition bugs, don't downgrade patch-bypass bugs, don't promote on WAF-hostility alone. Allow empty S on non-JVM manifests; promote auth-boundary normalization and native-code parser memory corruption when working outside JVM.

The discriminator + the auth-missing co-tag rule + the cross-ecosystem reframe are the durable wisdom. The rest is engagement-specific tuning.
