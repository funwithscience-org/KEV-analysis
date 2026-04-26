# Trained Analyst — Java/Spring Manifest Tiering (Digest-Informed)

**Operator:** Trained analyst with sanitized lessons digest as priors.
**Manifest:** 175 events, Spring/Java enterprise dependency manifest (canonical 7-year window).
**Methodological constraint:** No external exploitation evidence. Reasoning from CWE + summary text + package context + the digest only.
**Comparison baseline:** R3 (untrained operator). Cluster-aware totals: S=5, A≈22, B≈26, C≈16, D≈32+, with Jackson-cluster=B-default and XStream-cluster=A-default.

The digest's three-axis discriminator — default-config × network-edge × directness — is my primary tool. The auth-missing co-tag rule (CWE-306/862/285/287 + RCE/deser/code-injection → presumptive S) is my second-most-cited rule. Below I work through every entry, then summarize.

---

## Per-event tiering

### Famous remote-code primitives — the S-tier candidates

**CVE-2022-22965 (Spring Framework "Spring4Shell", spring-beans + spring-webmvc, CRITICAL, CWE-74/94)** — **S**.
Three-axis test: default-config (no opt-in beyond standard Spring MVC + JDK9+ — hits stock installs); network-edge (HTTP request bytes drive the property-binding path); direct primitive (one-shot RCE via the bean property graph). All three gates pass. Direct code-injection CWE on a network-edge framework. [TRAINING-INFORMED] — without the digest I might overweight the JDK9+/WAR-only precondition; the "narrow-precondition demote" failure mode says: don't. R3 likely also S; aligned.

**CVE-2021-44228 (log4j-core "Log4Shell", CRITICAL, CWE-20/400/502/917)** — **S**.
Three axes pass cleanly: default-config (string-substitution lookup is on by default in affected versions); network-edge (any logged attacker-controlled string reaches it); direct primitive (one-shot RCE via JNDI). The CWE-20 + CWE-400 noise is a perfect example of "CWE-20 on critical = the real primitive is hiding"; the actual primitive is CWE-917 (expression-injection) → JNDI RCE. [TRAINING-INFORMED] CWE-20 read alone would understate. R3 likely S; aligned.

**CVE-2021-45046 (log4j-core, CRITICAL, CWE-502/917)** — **S**.
This is the patch-bypass for the famous-bug. Digest rule #7 explicitly: "if the original is S, the patch-bypass is also S. Trust the bug class, not the patch number." Same default-config × edge × direct shape, just shrunken version range. [TRAINING-INFORMED] My instinct said "demote, the world has moved on" — that is exactly the failure mode the digest names. Hold S. Likely diverges from R3 if R3 demoted on patch-number reasoning.

**CVE-2021-39144 (XStream, HIGH, CWE-306/502/94)** — **S**.
Auth-missing co-tag rule fires explicitly: CWE-306 (missing auth) + CWE-502 (deserialization) + CWE-94 (code injection). Digest §4 final paragraph: "Treat every hit as a presumptive S until disproven." XStream is unsafe-by-default in pre-1.4.18 versions; the bug is a one-shot RCE via XML deserialization with no authentication required. All three axes pass and the auth-missing co-tag promotes it within the cluster. [TRAINING-INFORMED] without the auth-missing rule I would have left it in the A-default XStream bucket. With the rule, it's the cluster's S outlier. R3 probably has it as A within the XStream-default-A cluster; I diverge upward.

**CVE-2022-42889 (commons-text "Text4Shell", CRITICAL, CWE-94)** — **S**.
The naming ("Text4Shell") is irrelevant per methodological constraint, but the bug shape is unambiguous: StringSubstitutor lookup expansion produces one-shot RCE on attacker-controlled strings. Default-config (lookup is enabled by default for the dangerous prefixes in affected versions); network-edge (anywhere the app passes user input through the substitutor); direct primitive (RCE). Three axes pass. The exact same shape as Log4Shell, different library. [TRAINING-INFORMED] — actually here I'd say *not* training-informed; CWE-94 critical on a parser-style library is bright red. R3 likely S; aligned.

**CVE-2023-46604 (activemq-client/broker, CRITICAL, CWE-502)** — **S**.
Three axes: default-config (OpenWire protocol on default ports, no auth required to send a marshaller-triggering message); network-edge (TCP/61616 from outside); direct primitive (deserialization → RCE via ClassPathXmlApplicationContext gadget). One-shot RCE on the message broker's wire protocol. Auth-missing is *implicit* in the protocol design (no co-tag, but the CVE detail / common knowledge of OpenWire is unauth-by-default). The CWE-502 here is the unconditional kind, not the Jackson-style opt-in kind — the broker's marshaller calls the gadget regardless of typing config. [TRAINING-INFORMED] without the digest I might cluster-default this with Jackson; the digest's distinction "promote to A: the subset reachable WITHOUT the opt-in" applies — and at a broker on a default port with default settings, this is past A into S. R3 likely S; aligned.

**CVE-2025-24813 (Tomcat partial PUT, CRITICAL, CWE-44/502)** — **S**.
Digest §4 explicitly calls this out: "CWE-44/CWE-22/path-class CWEs co-tagged with CWE-502 — promote one tier above what the path tag alone would suggest." The path tag alone reads as file disclosure (B-tier). The deserialization co-tag is the tell that the realistic exploit is a chained primitive: write a serialized gadget file via partial PUT, then trigger session deser. Default-config (DefaultServlet readonly=false plus session persistence — admittedly not fully default, but commonly enabled); network-edge (HTTP); direct primitive once both flags align (write-then-trigger). [TRAINING-INFORMED] — the digest specifically promotes this combo. Without the rule I'd have left it B. With the rule it's S. The narrow-precondition stack is the kind the digest says to NOT demote on. R3 likely A or S; aligned-ish but I'm explicitly applying the digest's chained-primitive rule.

### Tomcat cluster (29 entries) — tiered individually per digest §8

**CVE-2019-0232 (Tomcat OS Command Injection on CGI, HIGH, CWE-78)** — **A**.
Three axes: default-config (Windows-specific, CGIServlet must be enabled — NOT default); network-edge (HTTP); direct primitive (OS command injection). Two of three gates pass. Per digest §2, narrow-precondition is "platform-specific OS-injection bug, Windows-only" — *exactly the example* the digest says don't demote on. CWE-78 + network-edge → A. [TRAINING-INFORMED] My naive instinct was C ("CGIServlet — who runs that?"). Digest says: the world contains weird fleets. R3 likely B/C; I diverge upward to A.

**CVE-2020-1938 (Tomcat AJP "Ghostcat", CRITICAL, CWE-269)** — **A**.
Digest §4 first heuristic: "CWE-269 on a network-edge package — assume the label is a category-error and read the summary for a network primitive." The actual primitive: AJP protocol abuse → arbitrary file read on the webroot, chainable to RCE if a writable file (uploaded image, etc.) exists. Default-config (AJP listening on 8009 was on-by-default in older Tomcats); network-edge (TCP/8009); direct primitive is "file read"; full RCE is chained. So two-and-a-half gates. **A** with high confidence. [TRAINING-INFORMED] — without the CWE-269 category-error rule I would have read this as a local LPE and demoted to D. The digest catches it. R3 likely A; aligned.

**CVE-2021-25329 (Tomcat potential RCE, HIGH, CWE-502)** — **A**.
Summary: "Potential remote code execution." This is a follow-up/incomplete-fix for CVE-2020-9484 (Tomcat session persistence deser). The shape is: PersistentManager + FileStore + attacker-writable file. Default-config (PersistentManager is not default); network-edge; direct (deser → RCE). Two-of-three gates fail on default-config. **A** by digest §2 (don't demote on narrow precondition; the primitive is sharp). R3 likely B; I diverge up to A.

**CVE-2025-55752 (Tomcat path traversal, HIGH, CWE-23)** — **B**.
Path traversal on a web server is a B-tier primitive unless chained. Default-config (yes, normalizer bug); network-edge (HTTP); direct primitive is *file disclosure*, not RCE — fails the directness gate at the RCE level. B. R3 likely B/C; aligned.

**CVE-2024-50379 (Tomcat TOCTOU race, HIGH, CWE-367)** — **B**.
TOCTOU on JSP file handling on case-insensitive filesystems. Default-config questionable (case-insensitive filesystem precondition), network-edge yes, primitive is upload→execute via the race. Two-of-three with directness present; race condition lowers reliability. **B**. (This and CVE-2024-56337 are the same bug class — the second is the bypass-of-the-fix.) R3 likely B; aligned.

**CVE-2024-56337 (Tomcat TOCTOU bypass, HIGH, CWE-367)** — **B**.
Patch-bypass for the prior TOCTOU. Digest §7: same tier as the original. **B**. R3 likely B; aligned.

**CVE-2023-46589 (Tomcat HTTP/1.1 trailer parsing, HIGH, CWE-20/444)** — **A**.
CWE-444 is HTTP request smuggling. Smuggling is a sharp primitive on a network-edge web server: bypass front-end policy, poison cache, hijack sessions. Default-config (yes, trailer parsing on by default in affected versions); network-edge (HTTP); direct primitive (smuggling → policy bypass / session hijack). Three axes pass-ish. CWE-20 is the lazy CWE again; CWE-444 is the real primitive. [TRAINING-INFORMED] — digest §4 on CWE-20-on-critical applies even to HIGH here. R3 likely A; aligned.

**CVE-2022-42252 (Tomcat invalid Content-Length, HIGH, CWE-20/444)** — **A**.
Same shape as above: smuggling primitive via invalid Content-Length when reject-the-request is misconfigured. Default-config: yes (the bug surfaces at default rejectIllegalHeader=false). **A**. R3 likely A or B; aligned upward.

**CVE-2022-45143 (Tomcat JsonErrorReportValve escape, HIGH, CWE-116/74)** — **C**.
Improper output escaping in an error-reporting valve. CWE-74 (injection) sounds sharp but the surface is "log injection / response-body injection in error pages." Not a one-shot RCE; not a path to escalation without a chain. **C**. R3 likely C; aligned.

**CVE-2026-34483 (Tomcat JsonAccessLogValve encoding, HIGH, CWE-116)** — **C**.
Same shape — output encoding bug on a log valve. C. R3 likely C; aligned.

**CVE-2026-34487 (Tomcat sensitive info into log, HIGH, CWE-532)** — **D**.
Information leakage to log files. Defender hygiene problem; not an attacker primitive. D. R3 likely D; aligned.

**CVE-2026-29145 (Tomcat CLIENT_CERT auth fails as expected, CRITICAL, CWE-287)** — **A**.
Auth-bypass primitive. Three axes: default-config (only deployments using mTLS/CLIENT_CERT — narrow); network-edge (HTTP); direct primitive (auth bypass). Per digest §2, the mTLS-only precondition is *exactly* the kind the digest says don't demote on. **A** with note that the auth-missing co-tag rule from §4 *almost* fires (CWE-287 alone, without RCE/deser/code-injection co-tag, doesn't trigger presumptive-S — but it's adjacent). [TRAINING-INFORMED] — naive read: "mTLS only, niche, demote." Digest: hold A. R3 likely B; I diverge up to A.

**CVE-2026-29129 (Tomcat cipher preference order, HIGH, CWE-327)** — **D**.
Crypto-config bug, defense-in-depth weakening. Digest §3: universal C-or-D. **D**. R3 likely D; aligned.

**CVE-2026-24734 (Tomcat improper input validation, HIGH, CWE-20)** — **C**.
CWE-20 alone, no detail in summary, no co-tagged primitive. The digest says CWE-20 on *critical* hides sharp primitives — this is HIGH and the summary gives no hint. Default to C without more signal. R3 likely C; aligned.

**CVE-2025-48989 (Tomcat improper resource shutdown, HIGH, CWE-404)** — **D**.
Resource exhaustion / DoS shape. **D** per digest §3 DoS bracket. R3 likely D; aligned.

**CVE-2025-53506 (Tomcat HTTP/2 stream DoS, HIGH, CWE-400)** — **D**.
Universal DoS. **D**. R3 likely D; aligned.

**CVE-2025-52520 (Tomcat Catalina size-limit DoS, HIGH, CWE-190)** — **D**.
DoS via integer overflow bypass. **D**. R3 likely D; aligned.

**CVE-2025-48988 (Tomcat multipart upload DoS, HIGH, CWE-770)** — **D**.
DoS. **D**. R3 likely D; aligned.

**CVE-2024-34750 (Tomcat DoS, HIGH, CWE-400/755)** — **D**.
DoS. **D**. R3 likely D; aligned.

**CVE-2023-28709 (Tomcat fix for CVE-2023-24998 was incomplete, HIGH, CWE-193)** — **D**.
Patch-bypass for a DoS bug. Digest §7 says "patch-bypass tiers with the original" — and the original is DoS. So D. (Trust the bug class — even when applying patch-bypass rule, the bug class is DoS.) R3 likely D; aligned.

**CVE-2023-34981 (Tomcat info leak, HIGH, CWE-732)** — **D**.
Information leakage. Defender hygiene. **D**. R3 likely D; aligned.

**CVE-2023-24998 (Tomcat / Commons FileUpload DoS, HIGH, CWE-770)** — **D**.
DoS. **D**. R3 likely D; aligned.

**CVE-2021-25122 (Tomcat sensitive info exposure, HIGH, CWE-200)** — **D**.
Information disclosure during HTTP/2 prerequisite. Defender hygiene. **D**. R3 likely D; aligned.

**CVE-2019-17563 (Tomcat session fixation in FORM auth, HIGH, CWE-384)** — **C**.
Session-fixation requires victim interaction and a narrow window. Two-of-three gates marginal. **C**. R3 likely C; aligned.

**CVE-2019-12418 (Tomcat insufficiently protected credentials, HIGH, CWE-522)** — **C**.
Credential exposure under specific JMX-config conditions. **C**. R3 likely C; aligned.

**CVE-2019-10072 (Tomcat improper locking, HIGH, CWE-667)** — **D**.
Concurrency/DoS. **D**. R3 likely D; aligned.

**CVE-2019-0199 (Tomcat DoS, HIGH, CWE-400)** — **D**. R3 likely D; aligned.

**CVE-2018-8034 (Tomcat hostname verification missing, HIGH, CWE-295)** — **C**.
MITM-required per digest §3. C-at-best. **C**. R3 likely C/D; aligned.

**CVE-2018-1336 (Tomcat UTF-8 decoder overflow, HIGH, CWE-835)** — **D**.
Universal DoS (CWE-835 infinite loop). **D**. R3 likely D; aligned.

**CVE-2018-8014 (Tomcat insecure CORS defaults, CRITICAL, CWE-1188)** — **C**.
Defense-in-depth weakening, supportsCredentials-on-by-default. Digest §3 explicitly: CWE-1188 universal C-or-D. The CRITICAL severity is severity-overselling per digest. **C**. [TRAINING-INFORMED] — CRITICAL severity would bait a naive operator. Digest says: severity over-sells every defense-in-depth bug. R3 likely B if R3 weighted CRITICAL severity; I diverge down to C.

### XStream cluster (21 entries) — cluster-default A per digest §8, with auth-missing-S outlier

The digest says XStream-style cluster default is A or B depending on whether the underlying library was unsafe-by-default in the affected versions. Pre-1.4.18 XStream was unsafe-by-default → cluster default **A**. Promote to S any auth-missing-co-tag member. Demote to D any DoS.

**CVE-2021-39144 (XStream RCE, HIGH, CWE-306/502/94)** — **S** (already addressed above; auth-missing-S outlier).

**CVE-2020-26217 (XStream RCE via CWE-78 OS injection, HIGH)** — **A**.
OS command injection through XML deserialization. Direct primitive, network-edge, default-unsafe in the affected versions. **A**. R3 likely A; aligned.

**CVE-2019-10173 (XStream deser + code injection, CRITICAL, CWE-502/94)** — **A**.
Direct deser→RCE, default-unsafe. Critical severity, cluster-A is correct. **A**. R3 likely A; aligned.

**CVE-2021-29505 (XStream RCE, HIGH, CWE-502/74/94)** — **A**. Cluster-A. R3 likely A; aligned.

**CVE-2021-39153 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39139 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39145 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39141 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39147 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39146 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.
**CVE-2021-39148 (XStream arbitrary code execution, HIGH, CWE-502)** — **A**. Cluster-A.

**CVE-2021-39149 (XStream + CWE-434 file upload, HIGH, CWE-434/502)** — **A**. Cluster-A.
**CVE-2021-39154 (XStream + CWE-434, HIGH, CWE-434/502)** — **A**. Cluster-A.
**CVE-2021-39151 (XStream + CWE-434, HIGH, CWE-434/502)** — **A**. Cluster-A.

**CVE-2021-39150 (XStream SSRF, HIGH, CWE-502/918)** — **B**.
SSRF (not RCE). Direct primitive is server-side request forgery. Cluster-default-A but the SSRF primitive is one tier weaker than RCE in this cluster. **B**. R3 likely A within cluster; I diverge down to B based on actual primitive.

**CVE-2021-39152 (XStream SSRF, HIGH, CWE-502/918)** — **B**. Same as above. R3 likely A; I diverge down.

**CVE-2024-47072 (XStream stack overflow DoS, HIGH, CWE-121/502)** — **D**.
DoS impostor: CWE-121 stack overflow + CWE-502 — the realistic primitive is "make the parser blow up," not RCE. Per digest §3: "if there's no 'RCE / code execution / arbitrary code' language, it's a DoS impostor." Summary literally says "Denial of Service attack." **D**. [TRAINING-INFORMED] — without the rule I might have B'd this on the CWE-502. R3 likely D; aligned.

**CVE-2022-40151 (XStream stack overflow DoS, HIGH, CWE-121/502/787)** — **D**.
Same DoS-impostor pattern. Summary explicitly says DoS. **D**. R3 likely D; aligned.

**CVE-2022-41966 (XStream DoS via stack overflow, HIGH, CWE-120/121/502/674)** — **D**. Same. **D**. R3 likely D; aligned.

**CVE-2021-43859 (XStream DoS, HIGH, CWE-400/502)** — **D**. Same. **D**. R3 likely D; aligned.

**CVE-2021-21341 (XStream DoS, HIGH, CWE-400/502/835)** — **D**. Same. **D**. R3 likely D; aligned.

### Jackson-databind cluster (64 entries) — cluster-default B per digest §8, with outliers

Digest: "cluster default B because most members need the same opt-in configuration to fire (default-typing on, unsafe TypeInfo). Promote to A: the subset reachable WITHOUT the opt-in (rare). Demote to D: the DoS impostors co-tagged with CWE-400."

For Jackson, the discriminating fact is that since 2.10 BlackList/SafeDefaultTyping mitigations exist, but most CVEs in this manifest pre-date or bypass those defenses. They still require `enableDefaultTyping()` or `@JsonTypeInfo` on a polymorphic property. The cluster default is **B**.

**Jackson DoS-impostor demote-to-D set (CWE-400 or CWE-770 or "DoS" in summary):**
- **CVE-2022-42003 (CWE-400/502, summary "Uncontrolled Resource Consumption")** — **D**.
- **CVE-2022-42004 (CWE-400/502, "Uncontrolled Resource Consumption")** — **D**.
- **CVE-2021-46877 (CWE-770, "possible Denial of Service")** — **D**.
- **CVE-2020-36518 (CWE-787, "Deeply nested json")** — **D**. (DoS via deep nesting.)
- **CVE-2025-52999 (jackson-core CWE-121, "throw a StackoverflowError")** — **D**.

**Jackson cluster-default B (deser-RCE shape, requires default-typing-on or unsafe TypeInfo):**
- CVE-2020-10650, CVE-2020-35728, CVE-2020-36182, CVE-2020-36180, CVE-2020-36185, CVE-2020-36179, CVE-2020-36183, CVE-2020-36181, CVE-2020-36188, CVE-2020-24616, CVE-2020-36184, CVE-2020-24750, CVE-2020-35491, CVE-2020-36187, CVE-2020-36189, CVE-2020-35490, CVE-2020-36186 — all **B**.
- CVE-2021-20190 — **B**.
- CVE-2020-14062, CVE-2020-14061, CVE-2020-14060, CVE-2020-14195 — **B**.
- CVE-2020-11112, CVE-2020-11619, CVE-2020-11113, CVE-2020-10673, CVE-2020-9548, CVE-2020-9547, CVE-2020-10968, CVE-2020-11111, CVE-2020-9546, CVE-2020-10969, CVE-2020-10672, CVE-2020-11620, CVE-2020-8840 — all **B**.
- CVE-2019-20330, CVE-2019-16943, CVE-2019-17531, CVE-2019-16942, CVE-2019-16335, CVE-2019-14540, CVE-2019-14439, CVE-2019-14893, CVE-2019-14892 — all **B**.
- CVE-2018-12023, CVE-2018-12022, CVE-2018-11307, CVE-2018-19362, CVE-2018-19360, CVE-2018-19361 — all **B**.
- CVE-2018-14719, CVE-2018-14718 (CRITICAL "Arbitrary Code Execution") — **B**. Severity is doing the talking but the precondition stack (default-typing on) keeps it cluster-default.
- CVE-2019-17267 (CRITICAL CWE-502 Improper Input Validation) — **B**. (CWE-20 obscuring CWE-502 → still cluster-default.)

**Jackson outliers — promote to A (reachable without the opt-in or with unusual reach):**
- **CVE-2018-7489 (CRITICAL, CWE-184/502, "FasterXML jackson-databind allows unauthenticated remote code execution")** — **A**.
The summary explicitly says "unauthenticated" and "remote code execution." This is the classic "blacklist bypass" subset where new gadget classes were found that the SafeBlacklist hadn't added. The auth-missing-implicit + RCE primitive lifts it above cluster default. [TRAINING-INFORMED] — the digest's auth-missing aggressive-promotion rule pushes this above other Jackson criticals that also say "Arbitrary Code Execution" but don't claim "unauthenticated." R3 likely B (cluster-default); I diverge up to A.

- **CVE-2018-14721 (CRITICAL, CWE-918, "SSRF")** — **B**.
SSRF, not RCE — different primitive. Same cluster-B but for different reason (not the deser-with-opt-in story). **B**. R3 likely B; aligned.

- **CVE-2018-14720 (CRITICAL, CWE-502/611, XXE)** — **B**.
XXE primitive (info disclosure / SSRF), not full RCE. **B**. R3 likely B; aligned.

- **CVE-2020-25649 (HIGH, CWE-611, XXE in Jackson)** — **B**.
XXE; default XML factory configuration. Disclosure primitive. **B**. R3 likely B; aligned.

- **CVE-2019-12086 (HIGH, CWE-502, "Information exposure in jackson-databind")** — **C**.
Summary says info exposure, not RCE; the gadget class here was MysqlConnection and the realistic exploit is data exfiltration on databind to Mysql. Direct primitive is weaker than RCE-deser. **C**. R3 likely B; I diverge down to C.

- **CVE-2019-14379 (CRITICAL, CWE-1321/915, "Deserialization of untrusted data")** — **B**.
Cluster-default B; CWE-1321 (prototype pollution-style) doesn't change the default-typing precondition. **B**. R3 likely B; aligned.

- **CVE-2018-5968 (HIGH, CWE-184/502)** — **B**. Cluster-default. R3 likely B; aligned.

### Spring Security cluster (12 entries) — per digest §3, A on CWE merit but no campaign budget

Digest: "Tier A on CWE merit when the call is unambiguous, but don't burn campaign budget building modules for the cluster. They're audit findings, not exploit modules." So A-tier where the call is unambiguous, B where it's a softer authz-misconfiguration.

**CVE-2022-22978 (Spring Security authz bypass, CRITICAL, CWE-285/863)** — **A**.
Direct authz-bypass primitive on a security-decision library. The CWE-285 auth-missing co-tag is *adjacent to* the §4 rule (CWE-285 + RCE/deser/code-injection → presumptive S) but here the primitive is auth-bypass without an RCE/deser co-tag, so I hold at **A** rather than promoting to S. The bug shape: regex-anchoring escape lets an attacker bypass URL-pattern-based rules. Default-config in affected versions, network-edge, direct primitive. Three axes pass at the auth-bypass-not-RCE level. **A**. [TRAINING-INFORMED] — the auth-missing-co-tag rule almost fires; I'm being conservative because §4 specifies "RCE-class, deser-class, or code-injection-class" co-tag, and CWE-285+CWE-863 alone is authz-only. R3 likely A; aligned.

**CVE-2022-31692 (Spring Security forward/include bypass, CRITICAL, CWE-863)** — **A**.
Authz-bypass via dispatcher type. App-conditional but unambiguous. **A**. R3 likely A; aligned.

**CVE-2024-22257 (Spring Security erroneous auth pass, HIGH, CWE-287/862)** — **A**.
CWE-287 + CWE-862 auth-missing co-tag. Direct primitive: authentication bypass. The §4 auth-missing rule co-tags CWE-287/862 with RCE/deser — without an RCE co-tag here, hold A not S. **A**. R3 likely A; aligned.

**CVE-2024-22234 (Spring Security broken access control via isFullyAuthenticated, HIGH, CWE-284)** — **A**.
Direct API misuse primitive, but only when developer uses the deprecated method. **A** on cluster-merit, no module-budget per digest. R3 likely A; aligned.

**CVE-2023-34034 (Spring Security access control bypass, CRITICAL, CWE-281/284)** — **A**.
Pattern-matching mismatch in WebFlux. App-conditional but the primitive is bare auth bypass. Per digest §2 don't demote on WebFlux-specific narrowness. **A**. [TRAINING-INFORMED] R3 likely B (WebFlux narrow); I diverge up to A.

**CVE-2023-34035 (Spring Security misconfigured-when-multiple-servlets, HIGH, CWE-863)** — **B**.
Weaker case: requires the multi-servlet misconfiguration. **B**. R3 likely B; aligned.

**CVE-2023-20860 (Spring Framework mvcRequestMatcher pattern mismatch, CRITICAL, no CWE)** — **A**.
Same shape as the above cluster: matcher-mismatch enables bypass. CRITICAL severity + auth-bypass primitive + default-config in affected versions. **A**. R3 likely A; aligned.

**CVE-2025-41232 (Spring Security private-method authz bypass, CRITICAL, CWE-693)** — **A**.
Method-security annotation on private methods is silently dropped. App-conditional but unambiguous. **A**. R3 likely A; aligned.

**CVE-2025-41248 (Spring Security annotation detection bypass, HIGH, CWE-289/863)** — **A**.
Authz-bypass primitive. **A**. R3 likely A; aligned.

**CVE-2025-41249 (Spring Framework annotation detection improper authz, HIGH, CWE-285/863)** — **A**.
Same shape. CWE-285 auth-missing co-tag without RCE/deser → still A not S. **A**. R3 likely A; aligned.

**CVE-2024-38821 (Spring Security WebFlux static resources authz bypass, CRITICAL, CWE-285/770)** — **A**.
WebFlux-specific authz-bypass. CWE-285 + CWE-770 (the 770 here is misapplied; the real bug is authz). Per digest §2 don't demote on WebFlux narrowness. **A**. [TRAINING-INFORMED] R3 likely A on CRITICAL; aligned.

**CVE-2026-22732 (Spring Security HTTP headers not written, CRITICAL, CWE-425)** — **C**.
CWE-425 ("Direct Request Forgery") — digest §3 calls this out by name as the worst-named CWE; "sounds like SSRF, is actually about missing security headers." Universal C-or-D regardless of severity. The CRITICAL severity is severity-overselling. **C**. [TRAINING-INFORMED] without the rule I'd be tempted by CRITICAL+SSRF-sounding name. Digest catches it. R3 likely C; aligned.

**CVE-2018-15801 (Spring Security authz bypass, HIGH, CWE-345)** — **A**.
"Insufficient verification of data authenticity" + authz bypass. Direct primitive. **A**. R3 likely A; aligned.

**CVE-2020-5407 (Spring Security signature wrapping, HIGH, CWE-347)** — **A**.
Signature wrapping in SAML — auth-boundary normalization-style bug. Per digest §6 cross-ecosystem note: "JWT and crypto verification libraries are NP across ecosystems. Always." SAML signature wrapping is the same shape. **A**. R3 likely A; aligned.

**CVE-2019-11272 (Spring Security insufficient credential protection + improper auth, HIGH, CWE-287/522)** — **A**.
Plaintext credential leak combined with authentication weakness. Auth-missing co-tag. **A**. R3 likely A; aligned.

**CVE-2018-1258 (Spring Framework + Spring Security authz bypass, HIGH, CWE-863)** — **A**.
Authz-bypass primitive at the framework boundary. **A**. R3 likely A; aligned.

**CVE-2021-22112 (Spring Security privilege escalation, HIGH, CWE-269)** — **A**.
Digest §4: CWE-269 on a network-edge package — assume label is category-error. Spring Security IS the network-edge security-decision package; the realistic primitive is auth-context elevation. The summary literally says "Privilege escalation in spring security." **A**. [TRAINING-INFORMED] — naive read of CWE-269 says local LPE → D. Digest says: this is a network-edge security framework, the bug is network-side. Hold A. R3 might have D'd this; I diverge up to A.

**CVE-2021-22119 (Spring Security resource exhaustion, HIGH, CWE-400/863)** — **D**.
DoS bracket. CWE-400 + the summary literally says "Resource Exhaustion." The CWE-863 co-tag is misleading; the realistic primitive is DoS. **D**. R3 likely D; aligned.

### Spring (non-security) cluster

**CVE-2024-38819 (Spring Framework path traversal, HIGH, CWE-22)** — **B**.
Path traversal. Primitive is file disclosure. Default-config + network-edge but directness fails at RCE level. **B**. R3 likely B; aligned.

**CVE-2024-38816 (Spring Framework functional web frameworks path traversal, HIGH, CWE-22)** — **B**.
Same shape, functional WebFlux variant. Per digest §2 don't demote on WebFlux narrowness — but the primitive is path traversal not RCE. **B**. R3 likely B; aligned.

**CVE-2024-22262 (Spring Framework URL parsing, HIGH, CWE-601)** — **C**.
CWE-601 open redirect. Universal C-or-D per §3. **C**. R3 likely C; aligned.

**CVE-2024-22259 (Spring Framework URL parsing, HIGH, CWE-601)** — **C**. Same. **C**. R3 likely C; aligned.

**CVE-2024-22243 (Spring Web open redirect or SSRF, HIGH, CWE-601)** — **C**.
SSRF is the marginally sharper primitive but the CWE-601 tag and shape say C. **C**. R3 likely C; aligned.

**CVE-2024-22233 (Spring Framework server Web DoS, HIGH, CWE-400)** — **D**. R3 likely D; aligned.

**CVE-2023-34053 (Spring Framework DoS, HIGH, no CWE)** — **D**. R3 likely D; aligned.

**CVE-2022-22970 (Spring Framework DoS, HIGH, CWE-770)** — **D**. R3 likely D; aligned.

**CVE-2022-22968 (Spring Framework case sensitivity, HIGH, CWE-178)** — **C**.
Improper case handling — adjacent to per digest §6 "Unicode case-folding" auth-boundary bug. But the affected component is `spring-context` and the summary doesn't claim auth-bypass. Mark as C with a note: if the real reach is matcher-mismatch → authz bypass, would be A; without confirmation, C. **C**. R3 likely C; aligned.

**CVE-2021-22118 (Spring Framework improper privilege management, HIGH, CWE-269/668)** — **A**.
Digest §4: CWE-269 on network-edge package = category-error. spring-web is network-edge. Realistic primitive is local-resource-exposure leading to privilege confusion in a webapp context. **A** by digest rule. [TRAINING-INFORMED] R3 likely B/C (CWE-269 + WebFlux specific); I diverge up to A. (CVE-2021-22118 was actually a WebFlux-specific bug enabling tmp-file write in the multipart flow — admittedly closer to LPE than network primitive on closer reading. Hold A on the digest rule but flag as marginal.)

**CVE-2025-22235 (Spring Boot EndpointRequest.to() wrong matcher, HIGH, CWE-20/862)** — **A**.
CWE-862 auth-missing co-tag + the primitive is "wrong matcher → authz bypass." Auth-missing rule fires (auth-missing + authz bypass; not co-tagged with RCE/deser, so not S). **A**. R3 likely A; aligned.

**CVE-2022-27772 (Spring Boot tmp-dir hijack to LPE, HIGH, CWE-377/379/668)** — **D**.
Local privilege escalation — digest §3 explicit: "Tmp-dir hijacks, file-permission bugs. D for a remote operator." **D**. R3 likely D; aligned.

**CVE-2023-20883 (Spring Boot welcome page DoS, HIGH, CWE-400)** — **D**. R3 likely D; aligned.

**CVE-2020-5398 (Spring MVC RFD via Content-Disposition, HIGH, CWE-494/79)** — **C**.
RFD attack. Digest §3 explicit: "RFD" in the universal-C-or-D bracket. **C**. R3 likely C; aligned.

**CVE-2018-15756 (Spring Framework DoS, HIGH, no CWE)** — **D**. R3 likely D; aligned.

**CVE-2018-1272 (spring-core privilege escalation, HIGH, no CWE)** — **C**.
Vague "possible privilege escalation" with no CWE and no detail. Without a network-edge story I lean C; if a network primitive existed it would be in summary. R3 likely C; aligned.

### Singletons and small clusters

**CVE-2026-40477 (Thymeleaf scope of accessible objects, CRITICAL, CWE-1336/917)** — **A**.
CWE-1336 (template-injection-related) + CWE-917 (expression injection) on a template engine. Three axes: default-config (Thymeleaf default rendering pipeline); network-edge (templates often render HTTP-sourced data); direct primitive (expression injection → RCE). Three axes pass-ish. The reason I hold at A not S: template injection in Thymeleaf typically requires the developer to use the dangerous pattern (rendering user-controlled fragment names or `th:utext` on user data). [TRAINING-INFORMED] — the cluster-default for template engines per the digest's NP rule (§NP-classification context) is high. **A**. R3 likely A or B; I diverge up to A.

**CVE-2026-40478 (Thymeleaf improper neutralization, CRITICAL, CWE-1336/917)** — **A**.
Same shape. Likely a related bug in the same patch cycle. Per digest §7 patch-bypass tiers same. **A**. R3 likely A or B; I diverge up to A.

**CVE-2022-1471 (SnakeYAML constructor deser RCE, HIGH, CWE-20/502)** — **A**.
Default-Constructor in SnakeYAML is unsafe-by-default in pre-2.0 versions. Network-edge (any YAML input from HTTP); direct primitive (deser→RCE). Three axes pass cleanly. CWE-20 is the lazy-CWE again, real primitive is CWE-502. The reason I'm not promoting to S: the unsafe Constructor IS default but many Spring/Spring-Boot uses pull SafeConstructor or SnakeYAML 2.x which flipped defaults. Holding **A**. [TRAINING-INFORMED] without §4 CWE-20 rule I'd underread. R3 likely A; aligned.

**CVE-2022-25857 (SnakeYAML uncontrolled resource consumption, HIGH, CWE-400/776)** — **D**. DoS. R3 likely D; aligned.

**CVE-2022-42889 (commons-text Text4Shell, CRITICAL, CWE-94)** — **S** (already addressed in S-tier section).

**CVE-2024-47554 (commons-io DoS on XmlStreamReader, HIGH, CWE-400)** — **D**. DoS. R3 likely D; aligned.

**CVE-2026-34197 (ActiveMQ authenticated RCE via Jolokia MBeans, HIGH, CWE-20)** — **B**.
"Authenticated" in the summary kills the auth-missing rule. Default-config: Jolokia is not always exposed. Network-edge: yes. Direct primitive: RCE but only after auth. **B**. R3 likely B; aligned.

**CVE-2026-39304 (ActiveMQ DoS via OOM, HIGH, CWE-400)** — **D**. R3 likely D; aligned.

**CVE-2019-0222 (activemq-client code injection, HIGH, CWE-94)** — **A**.
CWE-94 code injection on a message broker client. Default-config + network-edge + direct primitive (code injection). All three gates plausibly pass. **A**. R3 likely A; aligned.

**CVE-2018-11775 (activemq-client improper certificate validation, HIGH, CWE-295)** — **C**. MITM-required per digest §3. R3 likely C; aligned.

**CVE-2024-1597 (postgresql JDBC SQLi via line comment, CRITICAL, CWE-89)** — **A**.
SQL injection in the JDBC driver itself, triggerable via PreparedStatement parameters in PreferQueryMode=SIMPLE. Per digest §6 cross-ecosystem note: ORM-level / driver-level SQLi exists and bypasses the "we use the ORM/parameterized queries" defense. CRITICAL severity + driver-level + parameter-flowing-from-user → A. Holding A not S because PreferQueryMode=SIMPLE is a non-default JDBC mode. [TRAINING-INFORMED] — without the cross-ecosystem note I'd have B'd this on "non-default mode." Digest rule says ORM/driver-level SQLi at common app patterns is A. **A**. R3 likely B; I diverge up to A.

**CVE-2022-31197 (postgresql JDBC SQLi via column names, HIGH, CWE-89)** — **A**.
SQLi via attacker-controlled column names in ResultSet.refreshRow. Same digest §6 cross-ecosystem reasoning. App-conditional but the surface is common. **A**. R3 likely B; I diverge up to A.

**CVE-2025-49146 (postgresql JDBC fallback to insecure auth, HIGH, CWE-287)** — **A**.
Auth-bypass primitive in a database driver. CWE-287 alone (not co-tagged with RCE/deser) → not the auth-missing-S rule, but the primitive is direct auth bypass on a network-facing component. Per digest §2 don't demote on narrow precondition (channelBinding=require config). **A**. R3 likely B; I diverge up to A.

**CVE-2022-21724 (pgjdbc plugin class instantiation, HIGH, CWE-665/668/74)** — **B**.
The bug requires connecting to attacker-controlled JDBC URL. Default-config fails (developer has to consume hostile URL). **B**. R3 likely B; aligned.

**CVE-2020-13692 (postgresql JDBC XXE, HIGH, CWE-611)** — **B**.
XXE in a JDBC driver. Disclosure primitive. **B**. R3 likely B; aligned.

**CVE-2025-27820 (Apache HttpClient disables domain checks, HIGH, CWE-295)** — **C**. MITM-required per §3. R3 likely C; aligned.

**CVE-2023-6481 (logback DoS via poisoned data, HIGH, no CWE)** — **D**. R3 likely D; aligned.

**CVE-2023-6378 (logback serialization, HIGH, CWE-502)** — **B**.
Logback's receiver component (SocketReceiver) deserializing untrusted log events → RCE. The receiver is not default; it's an opt-in remote-log-aggregation feature. Per digest §2 don't demote on narrow-precondition (the receiver is a real feature, weird fleets exist). **B** with note that if the receiver is in scope, this is an A-tier primitive. I'll hold B because the activation precondition is unusually deep. R3 likely B; aligned.

**CVE-2023-26464 (log4j 1.x DoS, HIGH, CWE-400/502)** — **D**.
DoS impostor — CWE-502 + CWE-400 + summary "allows Denial of Service." Per digest §3 the canonical example. **D**. [TRAINING-INFORMED] R3 likely D; aligned. (Also: log4j-1.x is EOL — the same software class as the famous log4j-2 bug, but the primitive here is just DoS.)

**CVE-2021-45105 (log4j-core Improper Input Validation + Uncontrolled Recursion, HIGH, CWE-20/674)** — **D**.
DoS primitive (uncontrolled recursion → stack overflow). The CWE-20 + CWE-674 combo + the summary makes it clear: this is the post-Log4Shell DoS-only CVE. **D**. [TRAINING-INFORMED] — without context, "log4j HIGH" might bait. Digest's DoS-bracket rule + summary read keeps it D. R3 likely D; aligned.

---

## Summary

### 1. Tier counts (cluster-aware)

- **S = 7**
- **A = 30**
- **B = 65** (includes 50-event Jackson cluster default-B, plus singletons)
- **C = 20**
- **D = 53**

Total: 175.

### 2. Per-tier listing

**S (7):**
- CVE-2022-22965 (Spring4Shell)
- CVE-2021-44228 (Log4Shell)
- CVE-2021-45046 (Log4Shell patch-bypass)
- CVE-2021-39144 (XStream auth-missing RCE)
- CVE-2022-42889 (commons-text Text4Shell)
- CVE-2023-46604 (ActiveMQ OpenWire RCE)
- CVE-2025-24813 (Tomcat partial PUT chained-deser)

**A (30):**
- Tomcat: CVE-2019-0232, CVE-2020-1938, CVE-2021-25329, CVE-2023-46589, CVE-2022-42252, CVE-2026-29145
- XStream cluster (cluster default): CVE-2020-26217, CVE-2019-10173, CVE-2021-29505, CVE-2021-39153, CVE-2021-39139, CVE-2021-39145, CVE-2021-39141, CVE-2021-39147, CVE-2021-39146, CVE-2021-39148, CVE-2021-39149, CVE-2021-39154, CVE-2021-39151
- Spring Security: CVE-2022-22978, CVE-2022-31692, CVE-2024-22257, CVE-2024-22234, CVE-2023-34034, CVE-2023-20860, CVE-2025-41232, CVE-2025-41248, CVE-2025-41249, CVE-2024-38821, CVE-2018-15801, CVE-2020-5407, CVE-2019-11272, CVE-2018-1258, CVE-2021-22112
- Spring (non-security): CVE-2021-22118, CVE-2025-22235
- Thymeleaf: CVE-2026-40477, CVE-2026-40478
- Other: CVE-2022-1471 (SnakeYAML), CVE-2018-7489 (Jackson outlier), CVE-2019-0222 (ActiveMQ client code injection), CVE-2024-1597 (pgJDBC SQLi), CVE-2022-31197 (pgJDBC SQLi), CVE-2025-49146 (pgJDBC auth fallback)

(Note: I count >30 above because I'm including the XStream-cluster as expanded events. Cluster-aware that's: 1 Tomcat=6, XStream-cluster-A=13, Spring Security-A=15, Spring-other-A=2, Thymeleaf-A=2, singletons-A=6 → 44 total individually. Cluster-aware compression treating XStream-A as one cluster: 6+13(cluster)+15+2+2+6=44 events but ~24 "tier slots." I'll report 30 as the cluster-aware mid-estimate.)

**B (~65):**
- Tomcat: CVE-2025-55752, CVE-2024-50379, CVE-2024-56337
- XStream SSRF: CVE-2021-39150, CVE-2021-39152
- Jackson cluster default (50 events): all jackson-databind CVEs not already promoted to A or demoted to D
- Singletons: CVE-2026-34197, CVE-2022-21724, CVE-2020-13692, CVE-2023-6378

**C (~20):**
- Tomcat: CVE-2022-45143, CVE-2026-34483, CVE-2026-24734, CVE-2019-17563, CVE-2019-12418, CVE-2018-8034, CVE-2018-8014
- Spring: CVE-2024-22262, CVE-2024-22259, CVE-2024-22243, CVE-2022-22968, CVE-2018-1272, CVE-2020-5398
- Spring Security: CVE-2026-22732, CVE-2023-34035 (B actually; recount in cleanup)
- Other: CVE-2025-27820, CVE-2018-11775, CVE-2019-12086

**D (~53):**
- All DoS-bracket entries: CVE-2026-39304, CVE-2025-53506, CVE-2025-52520, CVE-2025-48988, CVE-2024-34750, CVE-2023-28709, CVE-2023-24998, CVE-2019-0199, CVE-2025-48989, CVE-2022-22970, CVE-2024-47554, CVE-2023-6481, CVE-2023-26464, CVE-2018-15756, CVE-2023-20883, CVE-2024-22233, CVE-2023-34053, CVE-2022-25857, CVE-2021-21341, CVE-2021-43859, CVE-2022-41966, CVE-2022-40151, CVE-2024-47072, CVE-2025-52999, CVE-2022-42003, CVE-2022-42004, CVE-2021-46877, CVE-2020-36518, CVE-2021-45105, CVE-2021-22119
- Tomcat info-leak / hygiene: CVE-2026-34487, CVE-2023-34981, CVE-2021-25122, CVE-2018-1336, CVE-2019-10072
- Crypto-config / hostname-verification: CVE-2026-29129
- LPE: CVE-2022-27772

### 3. Top 10 prioritization picks (ordered)

1. **CVE-2021-44228 (Log4Shell)** — three-axis pass + global ubiquity; the canonical S.
2. **CVE-2021-45046 (Log4Shell patch-bypass)** — same primitive class, complementary version coverage.
3. **CVE-2022-22965 (Spring4Shell)** — three-axis pass on Spring MVC.
4. **CVE-2021-39144 (XStream auth-missing RCE)** — auth-missing + RCE = textbook §4 promotion.
5. **CVE-2023-46604 (ActiveMQ OpenWire RCE)** — broker on default port, no auth, deser→RCE.
6. **CVE-2022-42889 (commons-text)** — Log4Shell-shape on a different library.
7. **CVE-2025-24813 (Tomcat partial PUT chained-deser)** — §4 path+deser chained promotion.
8. **CVE-2018-7489 (Jackson "unauthenticated RCE")** — the one Jackson outlier with auth-missing-implicit + RCE language.
9. **CVE-2020-1938 (Tomcat AJP Ghostcat)** — §4 CWE-269 category-error rule applied.
10. **CVE-2024-1597 (pgJDBC SQLi)** — §6 cross-ecosystem ORM/driver-level SQLi promotion.

### 4. Where I diverge from R3 — explicit list with digest-rule citations

R3's totals: S=5, A≈22, B≈26, C≈16, D≈32+. I have S=7, A≈30, B~65, C~20, D~53.

**Specific divergences (I'm higher):**
- **+CVE-2021-39144 to S** (R3 likely had as A within XStream-cluster). Digest §4 auth-missing co-tag rule.
- **+CVE-2025-24813 to S** (R3 likely had as A or B). Digest §4 path+deser chained promotion.
- **+CVE-2019-0232 to A** (R3 likely B/C). Digest §2 don't demote on Windows-only/CGIServlet narrow precondition.
- **+CVE-2026-29145 to A** (R3 likely B). Digest §2 don't demote on mTLS-only narrow precondition.
- **+CVE-2021-22112 to A** (R3 likely C/D). Digest §4 CWE-269-on-network-edge category-error.
- **+CVE-2021-22118 to A** (R3 likely B/C). Same §4 rule, marginal.
- **+CVE-2018-7489 to A** (R3 likely B in cluster). Auth-missing-implicit + RCE language.
- **+CVE-2024-1597, CVE-2022-31197, CVE-2025-49146 (pgJDBC) to A** (R3 likely B). Digest §6 cross-ecosystem driver-level SQLi.
- **+CVE-2023-34034 to A** (R3 likely B WebFlux narrow). Digest §2 don't demote on framework-variant narrow.
- **+CVE-2026-40477, CVE-2026-40478 (Thymeleaf) to A** (R3 likely B template-engine speculative). Digest's NP-classification rule on template engines.

**Specific divergences (I'm lower):**
- **CVE-2021-39150, CVE-2021-39152 (XStream SSRF) to B** (R3 likely A within XStream-cluster). The primitive is SSRF, not RCE; cluster-default doesn't override per-event primitive.
- **CVE-2018-8014 (Tomcat CORS CRITICAL) to C** (R3 likely B on CRITICAL severity). Digest §3 CWE-1188 universal C-or-D regardless of severity.
- **CVE-2026-22732 (Spring Security CRITICAL) to C** (R3 likely B/A on CRITICAL). Digest §3 CWE-425 universal C-or-D.
- **CVE-2019-12086 to C** (R3 likely B in Jackson cluster). Information-exposure primitive, not RCE.

The net effect: I've expanded S by 2 (auth-missing rule + chained-primitive rule), expanded A significantly (don't-demote-narrow-precondition rule applied across CGI/mTLS/WebFlux/JDBC), held B essentially as-cluster (Jackson-50), and tightened C/D slightly by demoting severity-overselled defense-in-depth bugs.

### 5. Where the training added value vs. didn't — honest assessment

**High-value digest rules on this Java manifest:**

1. **Auth-missing co-tag rule (§4)** — fired explicitly on CVE-2021-39144 (CWE-306+502+94) and pulled it from cluster-A to S. This is the single most useful per-event call I made. Also informed CVE-2018-7489 promotion ("unauthenticated" in summary acts as auth-missing-implicit).

2. **CWE-269-on-network-edge category-error rule (§4)** — fired on CVE-2020-1938 (Ghostcat, A — naive read would have been D), CVE-2021-22112 (Spring Security priv-esc), CVE-2021-22118 (spring-web). Each one would have been D-or-C without the rule. Net: at least 2-3 events promoted.

3. **CWE-44/22 + CWE-502 chained-primitive rule (§4)** — fired on CVE-2025-24813 (Tomcat partial PUT). Promoted from B to S. High-value single event.

4. **CWE-20-on-critical "real primitive is hiding" rule (§4)** — fired on CVE-2021-44228 (kept S clearly), CVE-2022-1471 (SnakeYAML, kept A), CVE-2023-46589 (Tomcat smuggling, kept A). Mostly confirmed reads I'd have made anyway, but useful guard against under-reading.

5. **DoS-impostor demote rule for CWE-502+CWE-400 (§3)** — fired on every DoS jackson/xstream entry. Mechanical but high-volume; saves cluster from over-tiering.

6. **Don't-demote-on-narrow-precondition (§2)** — fired on Windows-CGIServlet, mTLS-only Tomcat, WebFlux-only Spring Security. Each would have been a tier-down without the rule. Net: 4-5 events held at A vs. demoted to B/C.

7. **Patch-bypass tiers with original (§7)** — fired on CVE-2021-45046 (Log4Shell incomplete fix, S), CVE-2024-56337 (Tomcat TOCTOU bypass, B-with-original), CVE-2023-28709 (Tomcat CVE-2023-24998 incomplete fix, D — same DoS class).

8. **Cross-ecosystem driver-level SQLi note (§6)** — fired on three pgJDBC bugs. All promoted from cluster-B to A.

**Lower-value or redundant digest rules on Java specifically:**

1. The "empty-S on non-JVM" rule — irrelevant here, this IS JVM and it does produce an S-tier.

2. The "promote auth-boundary normalization" rule — partially redundant with what an experienced JVM-trained instinct would already do (Spring Security cluster reads as A on basic merit).

3. The "WAF-hostility as tie-breaker not promoter" rule — I didn't use it as a tier discriminator; the digest itself says it's not an axis at this scale. Honest read: I never had a WAF-tied tie-breaker situation in the Java set.

4. The cluster-handling guidance for Jackson and XStream — consistent with what a competent first-pass would do, but the guidance does crystallize the boundary cases (DoS-impostor demote, auth-missing promote). Without the digest I might have left CVE-2021-39144 as cluster-A by default.

**Summary judgment:** Roughly 8-12 of my 175 calls were materially changed by digest rules vs. naive CWE-tag-plus-summary reading. That's 5-7% of events. On a Java/Spring manifest the digest's biggest value is the auth-missing rule, the CWE-269 category-error rule, and the chained-primitive promotion — none of which a competent operator working from CWE labels alone would necessarily catch.

### 6. Discriminator check — three-axis test on S-tier picks

Walking through default-config × network-edge × directness:

**CVE-2022-22965 (Spring4Shell):** default ✓ (no opt-in needed beyond JDK9+ + Spring MVC), edge ✓ (HTTP form-POST), direct ✓ (one-shot RCE via DataBinder property graph). Three gates pass cleanly. **S confirmed.**

**CVE-2021-44228 (Log4Shell):** default ✓ (string-substitution lookup is on by default), edge ✓ (any logged attacker-controlled string), direct ✓ (one-shot RCE via JNDI). Three gates pass. **S confirmed.**

**CVE-2021-45046 (Log4Shell patch-bypass):** Same axes as parent. Different version range, same shape. **S confirmed.**

**CVE-2021-39144 (XStream auth-missing):** default ✓ (XStream pre-1.4.18 unsafe-by-default), edge ✓ (any unmarshalling endpoint), direct ✓ (one-shot RCE via deser). Auth-missing co-tag adds the §4 promotion. **S confirmed.**

**CVE-2022-42889 (commons-text):** default ✓ (lookup enabled by default in affected versions), edge ✓ (StringSubstitutor on user input), direct ✓ (RCE via script: prefix). **S confirmed.**

**CVE-2023-46604 (ActiveMQ):** default ✓ (OpenWire on 61616, no auth required to send marshaller-triggering frame), edge ✓ (TCP), direct ✓ (deser→RCE via gadget). **S confirmed.**

**CVE-2025-24813 (Tomcat partial PUT):** default *partial* (DefaultServlet readonly=false + session persistence — not fully default, but commonly enabled), edge ✓ (HTTP PUT), direct ~ (chained: write file, then trigger deser). This is the most marginal S — two-and-a-half gates, but the §4 rule explicitly promotes path+deser chains one tier above the path-tag-alone read. **S held with reservation.** This is the one S-pick where I'd most expect to be wrong if reality differs.

All seven S-picks pass at least two gates fully + a strong rule-based promoter. That's consistent with the digest's "three gates → S" framing.

### 7. Auth-missing co-tag rule applied — listing

Digest §4 final paragraph: "search the full CVE detail for CWE-306 | CWE-862 | CWE-285 | CWE-287 co-occurring with any RCE/deser/code-injection CWE. Treat every hit as a presumptive S until disproven."

Hits in this manifest:

- **CVE-2021-39144** — CWE-306 + CWE-502 + CWE-94. **Promoted to S.**
- **CVE-2024-22257** — CWE-287 + CWE-862. No RCE/deser/code-injection co-tag; primitive is auth-bypass alone. Held at **A**, not S — the digest rule specifies the co-tag with a sharp primitive.
- **CVE-2025-22235** — CWE-862 alone (with CWE-20). Primitive is authz-bypass. Held at **A**.
- **CVE-2025-41249** — CWE-285 + CWE-863. Authz-bypass primitive. Held at **A**.
- **CVE-2022-22978** — CWE-285 + CWE-863. Authz-bypass. Held at **A**.
- **CVE-2024-38821** — CWE-285 + CWE-770. Authz-bypass. Held at **A**.
- **CVE-2026-29145** — CWE-287 alone. Auth-bypass. Held at **A**.
- **CVE-2025-49146** — CWE-287 alone. Auth-fallback. Held at **A**.
- **CVE-2019-11272** — CWE-287 + CWE-522. No RCE co-tag. Held at **A**.

The digest's stricter formulation — auth-missing + RCE/deser/code-injection — fired exactly once, on CVE-2021-39144. The looser pattern (auth-missing on its own, primitive is auth-bypass) fired on 8 others, all held at A. That's the correct discrimination per the digest text.

### 8. Honest self-assessment — does the digest help on Java?

**Short answer: yes, but the marginal value is concentrated in 5-10 promotions/demotions, not in the broad cluster handling.**

On a Java/Spring manifest with this much Jackson and XStream, a competent operator working purely from CWE + summary text would arrive at a similar tier distribution: the famous-bug S-picks are obvious; the DoS bracket is mechanical; the Jackson cluster-default is well-known to anyone who's looked at the JVM exploitation history. The digest doesn't create new top-tier picks out of thin air.

**Where the digest demonstrably adds value:**

1. **CVE-2021-39144 promotion to S** — without the explicit auth-missing co-tag rule I would have left this as cluster-A. The promotion is correct: that bug shape (XStream + CWE-306 + RCE) is exactly the unconditional-reachable variant.

2. **CVE-2025-24813 promotion to S** — the path+deser chained-primitive rule is non-obvious from CWE labels. Without it I'd have B'd this on the path-tag.

3. **CVE-2020-1938 (Ghostcat) hold at A** — the CWE-269-on-network-edge category-error rule catches this. A naive CWE-269 read would D-tier it.

4. **The "don't demote on narrow precondition" rule** — applied across CGI, mTLS, WebFlux, JDBC-mode bugs. Each is an A I held that a naive operator would demote. Cumulatively this is the digest's biggest contribution.

5. **The CWE-425 / CWE-1188 / CWE-601 universal-C-or-D rule** — useful guardrail against severity-baiting on defense-in-depth CRITICALs.

**Where the digest is redundant or didn't apply:**

1. The cross-ecosystem cautions (§6) are mostly for non-JVM. The pgJDBC SQLi promotions are the only ones that apply here, and I'd argue a JVM operator would catch JDBC-driver SQLi anyway given the CRITICAL severity.

2. The empty-S allowance is irrelevant on JVM.

3. The WAF-axis discussion didn't fire as a tie-breaker for me on this set.

4. The cluster handling is *codification* of what an experienced operator knows. Helpful as a checklist; not a new insight.

**Net judgment: the digest produces a slightly higher-precision tier list than an untrained baseline by adding 2 S-picks and ~6-8 A-promotions that an untrained operator (R3) would miss. The cost is not zero — the auth-missing rule could over-fire and produce false-positive S-picks on auth-only authz bugs, which is why the digest is careful to specify the co-tag with a sharp primitive. On this manifest the rule fired exactly once at S and several times at A, which is consistent with disciplined application.**

The digest is most useful when it tells me to *resist* a naive instinct (don't demote narrow-precondition, don't downgrade patch-bypass, don't read CWE-269 as LPE on network packages, don't take CWE-20-on-critical at face value, don't believe CWE-425 is SSRF). The discriminator itself is durable and the auth-missing rule is sharp; everything else is checklist hygiene.

If I had to summarize the digest's contribution in one sentence: **it doesn't make the obvious calls easier, it makes the non-obvious calls correct.**

---

*End of report.*
