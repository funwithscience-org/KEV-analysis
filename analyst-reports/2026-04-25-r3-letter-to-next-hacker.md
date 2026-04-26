# Letter to the Next Hacker — What I Learned After Seeing the Answer Key

**Operator framing.** I ranked 175 events on a Spring/Java manifest blind. The answer key came back. Here's what to keep, what to throw away, and what nearly cost me a hit.

---

## 1. What I got right and would do again

The discriminator works. **Default-config × network-edge × direct-primitive.** All three gates open = S. Two gates open = A. Anything else = B or worse.

S-tier hit 5/5. Not a coincidence. The reason it works at small N is that all three gates are *binary properties of the bug, not statistical properties of the deployment population*. You're not predicting which targets will be vulnerable — you're filtering for bugs where the operator doesn't *need* to predict that, because the bug itself eliminates the conditional.

- Log4Shell: any logged HTTP header. You don't need to find a configuration; you need to find a server.
- ActiveMQ 46604: TCP 61616, default-on, no auth gate. The same.
- XStream 39144: CWE-306 in the tag list — the bug ships with "no auth needed" already proved.
- SnakeYaml 1471: unsafe constructor is the default. The only conditional is "does this app take YAML over the wire," which is a deployment question, not a config question.

The gate test compresses three independent questions ("can I reach it," "do I need a setting flipped," "do I get RCE in one shot") into one tier label. The compression is the value. Don't lose it chasing nuance.

**Use it again.** Don't replace it. Refine it on the margins.

---

## 2. What I got wrong — the "narrow surface" downgrade reflex

CVE-2019-0232. Tomcat CGI servlet, OS command injection, Windows-only. I tiered it B with this reasoning: "CGI servlet default-disabled, Windows-only — pre-condition stack excludes the vast majority of Tomcat installs."

That reasoning is correct in expectation and wrong in fact. Someone wrote the Metasploit module. The exploit-dev community will weaponize a sharp primitive with a narrow surface as long as the primitive is sharp enough — because writing the module once costs less than the lifetime value of finding even a few targets that match the precondition.

**Lesson for the next operator:** A narrow precondition does not justify a downgrade if the primitive is direct RCE on the wire. You're ranking *bugs*, not *fleets*. The world contains weird fleets. Windows Tomcat with CGI enabled is a real deployment in 2026 — print/badge servers, legacy intranet apps, vendor appliances that bundle Tomcat. None of those show up in your manifest model, but they exist, and someone is targeting them.

**New rule:** if a bug passes "default × edge × direct" *within its precondition stack*, tier it A regardless of how narrow the stack is. Treat the precondition as a "discovery cost" line item, not a "kill the tier" line item.

Three tags this catches that I missed or nearly missed:
- CGI-on-Windows (CVE-2019-0232)
- mTLS-CLIENT_CERT (CVE-2026-29145 — I got this right at A, but the same reflex was hovering)
- WebFlux-only (CVE-2024-38821 — same)

The reflex says "minority deployment, demote." Resist it. Bug shape decides tier; deployment count decides effort allocation, downstream.

---

## 3. Patterns to NOT bother with

Some patterns absorb your attention budget and yield zero. Skip them.

**The DoS bracket. Universal D.** CWE-400, CWE-770, CWE-674, CWE-835, CWE-1333. The Jackson DoS impostors (eight or nine of them — CVE-2022-42003, -42004, CVE-2025-52999, CVE-2020-36518, etc.) are CWE-502 co-tagged with CWE-400 and have no "RCE" or "code execution" language in the summary. The tell is the co-tag. Operator yield: zero. R3, R4, R5 — none of the DoS-bracket events showed up in the answer key. Confirmed across rounds.

**Spring Security auth-bypass cluster.** This stings, because R5 looked at the same dataset and promoted four of these to S on WAF-hostility logic. Zero exploited. The Spring Security cluster reads like an arsenal — regex matchers, mvcRequestMatcher mismatches, annotation detection, access control bypass. None of them showed up in KEV/Metasploit/ExploitDB. Why?

My current best read: these bugs are *application-conditional*, not library-conditional. Spring Security ships safe defaults; the bug surfaces when the app uses the specific feature in the specific wrong way. That makes per-target weaponization expensive — the operator can't write a generic module that hits "any Spring Security app." The exploit-dev community routes around them. They're real bugs and a manual pentester might exploit one in front of you, but they don't drive the published-module ecosystem.

**Tier them A when the CWE/severity demands, but don't burn budget building campaigns around them.** They're audit findings, not exploit modules.

**Open redirects, RFD, header-missing, defense-in-depth weakening.** CWE-601, CWE-425, CWE-1188, hostname-verification bugs in client libraries. Universal C-or-D. Severity scores oversell every one of them. The CWE-425 "Forced Browsing / Direct Request Forgery" name is the worst offender — it sounds like SSRF, it's actually "X-Frame-Options sometimes missing." Don't get baited.

**Local privilege escalation in a server-side library.** CVE-2022-27772 (spring-boot temp dir hijack). LPE on the build host. Not a remote primitive. D for a remote operator.

**MITM-requiring bugs.** httpclient5 hostname verification, activemq-client cert validation. C at best. The next operator either has on-path position or doesn't; if they have it, they have better primitives than these.

---

## 4. Patterns to actively LOOK for that I almost missed

The CWE label lies, often in the same direction. Generic CWEs hide sharp primitives. Three classes hit me hard:

**CWE-269 ("Improper Privilege Management") on a network-edge package.** CVE-2020-1938 Tomcat AJP. The CWE-269 reads like a local LPE. The actual primitive is unauthenticated arbitrary file read on TCP port 8009, chainable to RCE if you can write a JSP. The tag is wrong-by-genre. **Heuristic:** when you see CWE-269 on a network server (Tomcat, an MQ broker, a gateway), assume the label is a category-error and look for a network primitive in the summary. Don't trust the tag; read the words.

**CWE-20 ("Improper Input Validation") on anything.** This is the laziest CWE in the entire system. It absorbs bugs across primitives — code injection, deserialization, auth bypass, anything where "the input was bad." CVE-2026-34197 (ActiveMQ Jolokia → MBean → RCE) tagged CWE-20. CVE-2025-22235 (Spring Boot actuator exposure → heapdump → secrets → RCE) tagged CWE-20 + CWE-862. **Heuristic:** CWE-20 on a critical-severity bug means "read the summary; the real primitive is hiding." If the package is a network server or a security-decision component, default-assume the primitive is sharper than the tag.

**CWE-44 ("Path Equivalence") + CWE-502 in combination.** CVE-2025-24813 Tomcat partial PUT. CWE-44 alone reads like a path-traversal disclosure. The CWE-502 co-tag is the tell — there's a deserialization gadget at the end of the chain. The realistic primitive is "PUT a session file with an embedded gadget, GET as that session, server deserializes." **Heuristic:** any CWE-502 co-tagged with a path/file CWE on a server is a chained primitive, not a single-step bug. Worth promoting one tier above what the path-tag alone would suggest.

**The auth-missing co-tag rule.** I called this out in R3 and it held. Any RCE-class CVE co-tagged with CWE-306, CWE-862, CWE-285, or CWE-287 is more dangerous than the same primitive without the auth-missing co-tag. The auth-missing label is what turns "sometimes-reachable" into "always-reachable." CVE-2021-39144 in XStream had CWE-306 in the tags — that's the gem signal that promoted it from A-cluster to S.

**Practical scan rule:** when triaging a fresh manifest, search the full CVE detail (not just the headline CWE) for `CWE-306|CWE-862|CWE-285|CWE-287` co-occurring with any RCE/deser/code-injection CWE. Treat every hit as a presumptive S until disproven.

---

## 5. The WAF axis — should you use it?

R5 added WAF-hostility as a fourth axis. Net result on the same 175 events: no precision/recall improvement at S+A. The four new S-tier picks (Spring Security regex, mvcRequestMatcher, access control, annotation auth bypass) all turned out to have zero exploitation evidence. One correct upgrade (Tomcat AJP A→S) and one wrong downgrade (Log4Shell-45046 S→A). Net wash.

**My read:** WAF-hostility is not an independent axis at this dataset size. It's *implicit in network-edge × direct-primitive already*. AJP is WAF-hostile because it's a non-HTTP protocol — the network-edge gate already captures that, you just have to remember that "edge" includes non-HTTP edges. Log4Shell is WAF-hostile because the payload sits in a header that gets logged — but that's just "default × edge" again, the WAF axis adds nothing.

When the WAF axis fires *without* the underlying axes firing — Spring Security regex auth bypass, where the bug is in security logic and the payload looks like normal traffic — the bugs don't actually get exploited at scale. So WAF-hostility-as-promotion-signal is a false positive generator.

**But:** R3+R4 outcome data says, conditional on hacker-A, WAF-hostile bugs exploited at 25% vs WAF-friendly at 14%. So the axis is real signal — just not as a tier promoter.

**Recommendation:** use WAF-hostility as a **tie-breaker within A**, not as a promoter to S. When you have an A-tier event you're considering whether to weaponize first, weight WAF-hostility positively. Do not promote from A to S on WAF-hostility alone. Do not demote from S on the inverse argument either — that was R5's mistake on Log4Shell-45046.

The other thing the axis is genuinely useful for: **double-miss detection.** Of 8 NP+DI filter misses, 5 were also WAF-hostile. That's a structural blind spot — the events your filter rejects AND that your WAF can't see are the events you cannot afford to miss. Run WAF-hostility as a secondary check on the rejected pile. Anything that scores hostile on the rejected pile is a probable backstop candidate.

---

## 6. Cross-ecosystem cautions — when the manifest isn't JVM

R4 ran the same discriminator on a 181-event Django/Python manifest. **S-tier was empty.** This is the most surprising cross-round finding.

Python doesn't have an unconditional one-shot RCE shape the way JVM does. The deserialization gadget chains that drive S-tier on JVM (Jackson polymorphic, XStream allowlist absence, OpenWire constructor invocation, SnakeYaml unsafe constructor) don't have direct Python analogs. `pickle.load` is the obvious one and it's been killed at default in numpy and friends; the Python community ran a tighter ship on dangerous defaults.

What did get exploited on Django:
- **Paramiko SSH auth bypass (CWE-287)** — auth boundary, untrusted input, security decision
- **Django Unicode reset hijack (CWE-640)** — auth boundary, normalization mismatch
- **Pillow libwebp memory corruption (CWE-787)** — image library, native code, network-edge
- **Django ORM SQLi (CWE-89)** — direct primitive

All four landed in hacker-A on R4. None hit S. The pattern isn't deser-RCE; it's **auth-boundary input normalization + native-code memory corruption in image/parser libraries**.

**If you're handed a non-JVM manifest, recalibrate:**

- **Don't expect S-tier to fire.** Empty S is a valid outcome. The discriminator may produce S=0 on Python, Node, Go, Rust manifests because the language doesn't have the unconditional-deser shape.
- **Promote auth-boundary normalization bugs.** Unicode case-folding, header normalization, JWT alg confusion, OAuth state validation, password reset token comparison. These are A-tier in any language and may be the *highest* tier you get on non-JVM.
- **Promote native-code parser libraries.** libwebp, libxml2, image codecs, font parsers. Memory-corruption primitives in network-reachable parsers ship with the JVM-equivalent of "default × edge × direct" — they just don't get tagged that way.
- **JWT + crypto verification libraries are NP.** Always. Across ecosystems. The trust-boundary rule applies — pyjwt, jjwt, jose, BouncyCastle, cryptography. Tier them with the auth-bypass cluster.
- **WSGI/ASGI/Rack header handling is the Python/Ruby equivalent of Tomcat's request-line parsing.** Smuggling, normalization, and header-injection bugs there should be A even when CWE labels them generic.
- **ORM-level SQLi exists and bypasses "we use the ORM" defense** — same shape as the pgjdbc-1597 driver-SQLi. Search for it.

JVM-trained instinct undervalues: image-library memory corruption, Unicode normalization, JWT alg confusion. Adjust.

---

## 7. The Log4Shell trap

R5 down-tiered CVE-2021-45046 from S to A on the reasoning: "by the time the patch-bypass exists, perimeter rules are already deployed." Wrong. CVE-2021-45046 was actually exploited.

The reasoning sounds plausible. WAF rules deploy fast for famous bugs. The patch-bypass payload variants are minor. So the reachable population shrinks.

The reasoning is wrong because it assumes the operator gets only one shot at a fully-patched, fully-WAFed target. Reality: there is a long tail of unpatched, partially-patched, and stuck-on-the-bad-intermediate-version installs for every famous bug. The bypass-patch becomes the *more useful* exploit because it covers the cases where the operator has hit version-1-of-the-fix and bounced. Same payload class, complementary version coverage.

**Rule for the next operator:** *Trust the bug class, not the patch number.* If the original is S, the patch-bypass is also S. The CWE shape is unchanged, the primitive is unchanged, the network reach is unchanged. The only thing that changes is the version range, and that's a discovery question, not a tier question.

This applies broadly: Spring4Shell follow-ons, ProxyShell siblings, Struts2 patch-bypass cycles, Jackson's two-decade catch-and-patch loop. **Bug class tiers; patch number doesn't.** Don't downgrade a known-S primitive because the version window narrowed.

---

## 8. Allocation guidance — 5 days on a Spring/Java manifest

You have five days. Spring/Java manifest of similar shape (Spring core + Boot + Security, Tomcat embed, Jackson, XStream, Log4j, ActiveMQ, snakeyaml, the usual). Here's where I'd spend.

**Day 1 — S-tier sweep.** Four to six events maximum. Build, test, dial in.
- Log4Shell (44228 + 45046 as one weapon — same payload class)
- ActiveMQ OpenWire (46604) — port 61616 scan + module
- XStream unauth (39144) when XML endpoints present
- SnakeYaml unsafe constructor (1471) when YAML-over-HTTP confirmed in the target

These five are 5/5 hits in the answer key. They are the bedrock. If you can't make them work in a day, your tooling is wrong, not the targets.

**Day 2 — High-value A-tier with default-config-ish reach.** The events one notch below S where the conditional is small.
- Spring4Shell (CVE-2022-22965) — WAR-deployed, JDK 9+. Real, exploited, build the chain.
- Tomcat AJP (CVE-2020-1938) — internal-network engagements. Don't skip because CWE-269 looks dull.
- commons-text (CVE-2022-42889) — when StringSubstitutor is used on user input.
- Tomcat partial PUT (CVE-2025-24813) — when readonly=false.

**Day 3 — The hidden gems.** These are the events the NP+DI filter and your own bias may push down.
- pgjdbc driver-SQLi (CVE-2024-1597) — bypasses "we parameterize" defense
- Spring Boot actuator exposure (CVE-2025-22235) — heapdump → secrets → jolokia → RCE chain
- Tomcat CGI Windows (CVE-2019-0232) — yes, narrow surface, but the module exists. Spend an hour on it on the chance you hit a Windows Tomcat.
- Thymeleaf SSTI (40477/40478) — when template injection is reachable

**Day 4 — Spring Security cluster — but as audit findings, not modules.** Don't try to write a generic exploit for the cluster. Use it as a manual-pentest tool against single-target engagements. Regex-anchor (22978), forward/include (31692), method-security (41232) are the highest-yield manual targets.

**Day 5 — Cluster sweep at scale.** Jackson and XStream as cluster decisions. Don't tier individual CVEs. Decide:
- Is `enableDefaultTyping` on anywhere in the target codebase? If yes, the whole Jackson cluster is in play.
- Is XStream pre-1.4.18 anywhere? If yes, the whole cluster is in play.
- Test for the cluster's default-config gate; if open, cycle through gadgets at the classpath level.

**What I would NOT spend the 5 days on:**
- The Spring Security auth-bypass cluster as an exploit-module target (do it manually, not as a campaign)
- Any DoS-bracket event at all
- MITM-requiring TLS bugs
- Open redirects, RFD, X-Frame-Options weakening
- Local LPE bugs

**One meta-rule:** budget the discovery cost separately from the weaponization cost. Some of these (CGI-Windows, mTLS, WAR-Spring) have low weaponization cost but real discovery cost. Build the modules first; let the discovery cost amortize across however many targets the world brings you.

---

## Closing

The discriminator is the asset. Don't break it trying to fix the edges. The edges fix themselves on a per-engagement basis: discovery cost and target distribution are what you tune for *after* the tier list, not what you encode *into* the tier list.

The two failure modes worth naming, because both R3 and R5 hit one each:

1. **Demoting on narrow precondition** (R3, CVE-2019-0232). Don't. Bug shape sets tier; precondition sets effort.
2. **Demoting on famous-bug WAF coverage** (R5, CVE-2021-45046). Don't. Trust the bug class, not the patch number.

Everything else in R3 was either right or close enough that further axis-tuning made it worse, not better. Hold the line on default × edge × direct. Promote auth-missing co-tags aggressively. Read the summaries, distrust generic CWEs, and remember that the answer key contains both Log4Shell and a Windows-only CGI module from 2019. Both are real. Tier accordingly.

— R3
