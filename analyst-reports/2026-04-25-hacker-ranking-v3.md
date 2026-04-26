# Hacker Ranking v3 — Full 175-event Spring/Java Manifest Backtest

**Operator framing.** I'm allocating exploitation effort across a Spring/Java enterprise dependency surface. I'm reasoning from the primitive, the precondition, and the default-config exposure — not from press fame. Tiers map to "would I pull this into my campaign tomorrow?"

**Tier definitions (carry-over from rounds 1-2):**
- **S** — default-config × network-edge × direct primitive. Build a working exploit today.
- **A** — RCE / full auth bypass with one annoying precondition.
- **B** — opportunistic chain-into. Limited primitive, niche surface, or significant ergonomics tax.
- **C** — restrictive conditions or weak primitive. Situational only.
- **D** — pass.

---

## Cluster: jackson-databind polymorphic-typing gadget chain (64 events)

**Members:** CVE-2017-7525 family — CVE-2018-7489, -11307, -12022, -12023, -14718, -14719, -14720, -14721, -19360, -19361, -19362, -5968; CVE-2019-12086, -14379, -14439, -14540, -14892, -14893, -16335, -16942, -16943, -17267 (CRITICAL), -17531, -20330; CVE-2020-8840, -9546, -9547, -9548, -10672, -10673, -10968, -10969, -11111, -11112, -11113, -11619, -11620, -14060, -14061, -14062, -14195, -24616, -24750, -25649 (XXE), -35490, -35491, -35728, -36179, -36180, -36181, -36182, -36183, -36184, -36185, -36186, -36187, -36188, -36189; CVE-2018-14721 (SSRF); CVE-2021-20190; CVE-2021-46877 (DoS — actually NOT in this group, see below).

**Tier rationale: B as a cluster, A for the bracket reachable without `enableDefaultTyping`.**

Every one of these is the same shape: attacker provides a JSON document with a `@class` discriminator, Jackson instantiates a class from the classpath that the gadget research community has named (C3P0, Spring's `JdbcRowSetImpl`, Logback's `JNDIConfigurator`, etc.), and that constructor or setter reaches a JNDI/JDBC/Runtime sink. The primitive is RCE. **But every gadget needs the same gate: either (a) `ObjectMapper.enableDefaultTyping()` is on globally, or (b) a deserialized field is typed as `Object`/`Serializable`/an interface and the attacker controls the type discriminator, or (c) the app uses `@JsonTypeInfo(use=Id.CLASS)` on attacker-reachable fields.**

In practice, modern Spring apps use Jackson via Spring MVC's body binding, which deserializes into typed DTOs. That's safe. The exploitable shape is custom code that takes JSON into an `Object`-typed field — common in legacy integration glue, message queues, cache layers, RPC libraries that re-serialize Java objects as JSON. So this cluster is **opportunistic-chain B** as the headline: high yield when the gate is open, totally unreachable when it isn't, and the operator has to discover which specific gadget classes are present on the target classpath.

**Promote-to-A subset: gadgets in widely-bundled libraries.** A small number of these gadgets land on classpaths so often that you can assume them: `JdbcRowSetImpl` (ships with the JRE), C3P0 (default Spring Boot connection pool used to be Tomcat JDBC, but C3P0 is still common), `JndiConfigurator`. If the app has `enableDefaultTyping` and ANY of those on the classpath you're done. If you have evidence default typing is on, lift the whole cluster to A.

**XXE/SSRF outliers within the cluster:**
- **CVE-2020-25649** (XXE in jackson-databind) — different primitive, same package. XXE → file read / SSRF, not RCE. The DOCTYPE-disabling default arrived late, so older-version targets still have the surface. **Tier B** as own primitive — XXE on a JSON parser is genuinely surprising, and the precondition is just "app deserializes XML through Jackson's XmlMapper or pre-2020 default parser." Auditors who saw "jackson-databind" and assumed JSON-only would miss this.
- **CVE-2018-14720, -14721** (XML external entity / SSRF) — same shape. **Tier B.**
- **CVE-2019-12086, -14892, -14893** (information exposure / polymorphic) — same primitive class as the rest but with information-disclosure framing. **Tier B with the cluster.**

**DoS outliers** (downgrade from cluster):
- **CVE-2020-36518, -25657 / -52999, -42003, -42004, -46877** — stack overflow / nested-input DoS. These are tagged CWE-502 or co-tagged with CWE-400 but the actual primitive is "make the parser blow up." **Tier D** — DoS in a stateless web app is roughly worthless to me.

**Single-CVE highlight inside the cluster: CVE-2017-7525 ancestor mechanic** — none of the listed CVEs is the original "no default typing required, just a Map<String,Object> field." Most of these listed bugs are **the slow patch-and-bypass cycle around the same primitive.** They're individually interchangeable; if I have one I have all on the same target.

**Net:** Cluster = **B**. Anything reachable without `enableDefaultTyping` (rare) and with a JRE-resident gadget = **A**.

---

## Cluster: XStream (21 events, CVE-2021-39139 through -39154 plus CVE-2019-10173, CVE-2020-26217, CVE-2021-21341, CVE-2021-29505, CVE-2021-43859, CVE-2022-40151, CVE-2022-41966, CVE-2024-47072, CVE-2021-39144)

**Tier rationale: A as a cluster, S for CVE-2021-39144.**

XStream is unsafe by default in older versions — unmarshalling untrusted XML loads classes from the XML directly. The 1.4.18 hardening introduced an allowlist, so post-fix XStream is safer than Jackson. But every one of these CVEs targets either pre-allowlist behavior or an allowlist bypass.

The exploitation primitive is the same as Jackson: send an XML payload that names a gadget class, XStream instantiates it, gadget reaches a sink. **Critical difference:** XStream's default config is *insecure-by-default* in the affected versions, so you don't need `enableDefaultTyping` equivalent — if the app calls `xstream.fromXML(userInput)` without configuring the allowlist, you have RCE.

**That moves the whole cluster up to A** because the precondition becomes "app uses XStream to deserialize untrusted XML" — easy to discover by sniffing for any endpoint that takes `application/xml` and matches XStream's quirky payload format.

**Promote to S:**
- **CVE-2021-39144** — tagged CWE-306 (missing authentication) alongside CWE-502, CWE-94. The CWE-306 is the tell — this isn't just "deserialization of attacker XML" but "deserialization of XML reachable without authentication." Combined with the default-config primitive, this is **S**: network-edge, default-config, direct RCE. (The summary "vulnerable to a Remote Command Execution attack" is also straight-up unhedged.)
- **CVE-2020-26217** — tagged CWE-78 (OS command injection via XStream). The CWE-78 is unusual for a deserialization library and suggests a default-reachable command-exec gadget without needing the broader gadget chase. **A, leaning S** — without seeing the patch I can't fully confirm default-config.
- **CVE-2019-10173** — CRITICAL severity, "Deserialization of Untrusted Data and Code Injection." Old enough that targets are likely to have the unsafe default. **A.**
- **CVE-2021-29505** — "Remote Command Execution attack" with CWE-94 + CWE-502. Direct RCE shape. **A.**
- **CVE-2021-39153, -39149, -39154, -39145, -39150 (SSRF), -39152 (SSRF), -39147, -39141, -39151, -39146, -39148, -39139** — the August 2021 batch of allowlist bypasses. Each is an "I found another gadget." Operator treatment: assume target has 1.4.17 or earlier and treat any one of these as a working chain. **A as a group.** The two SSRF variants (-39150, -39152) are slightly weaker — SSRF is useful but not RCE — call those **B**.

**DoS outliers** (downgrade from cluster):
- **CVE-2024-47072, CVE-2022-40151, CVE-2022-41966, CVE-2021-43859, CVE-2021-21341** — stack-overflow / recursive-collection DoS. **Tier D.** Stack overflow on a deserializer is annoying for ops but I'm not weaponizing it.

**Net:** XStream cluster = **A** (with CVE-2021-39144 promoted to **S**).

---

## Apache Tomcat (29 events) — individually tiered

Tomcat is a network-edge HTTP server. The primitive matters more than the package label.

- **CVE-2025-24813** — Tomcat partial PUT RCE / disclosure, CWE-44 + CWE-502. PUT-method enabled is a non-default but historically common config; partial PUT writing a file then reading it back as a session is a *direct* primitive once you find a server with `readonly=false`. The CWE-502 tag is doing real work — there's a deserialization gadget at the end of the chain. **Tier A.** Promotes to **S** if the operator can confirm `readonly=false` is the default on a deployment image (e.g., embedded Tomcat in some Spring Boot starter dev configs).
- **CVE-2020-1938** — "Improper Privilege Management" (CWE-269) on Tomcat. The CWE label is wrong. The actual primitive (this one I can recognize from the package + version + the AJP connector being default-on for a long stretch of Tomcat history) is reading arbitrary files via the AJP protocol on port 8009, sometimes leading to RCE if the attacker can write a JSP and then include it. Default-config exposure depends on whether 8009 is firewalled — frequently it isn't on internal networks. **Tier A** as a hidden-gem (CWE-269 oversells nothing and undersells everything). Pivots to **S** on internal pentests.
- **CVE-2025-55752** — Tomcat relative path traversal (CWE-23). HTTP path traversal on the request-line is a classic, but Tomcat's URL normalization is usually solid; this is likely a specific encoding/edge-case bypass. **B** — opportunistic; I'd test it but not build a campaign around it without confirming default reach.
- **CVE-2026-29145** — CWE-287, "CLIENT_CERT authentication does not fail as expected." Auth bypass on mutual-TLS. Critical severity. The precondition is "app uses CLIENT_CERT auth," which is more enterprise-internal than internet-edge. **A** — auth bypass is golden when reachable, but client-cert deployments are a minority surface.
- **CVE-2021-25329** — "Potential remote code execution" (CWE-502). The "potential" is doing work — this is a follow-up to a session-persistence + writable-FileStore chain. Needs a writable persistence directory and a specific config. **B.**
- **CVE-2019-0232** — Tomcat OS command injection (CWE-78) on Windows in CGI mode. CGI servlet is default-disabled. Windows-only. **B** — sharp primitive when it lands but precondition is narrow.
- **CVE-2018-8014** — CORS filter `supportsCredentials` insecure default (CWE-1188). Allows credentialed cross-origin. Real impact requires the CORS filter to be enabled (default-off but commonly turned on). The bug is that *when enabled*, the defaults are bad. Primitive is "ride a logged-in user's browser to access cross-origin endpoints." **B.**
- **CVE-2026-29145** (already covered above).
- **CVE-2024-56337, CVE-2024-50379** — TOCTOU race conditions (CWE-367). Race conditions on a multithreaded servlet container can yield file-write-then-execute primitives but require very specific deployment shape (case-insensitive filesystem + writable upload dir + running as JSP). **C** — bordering B on Windows targets.
- **CVE-2023-46589** — request smuggling (CWE-444). Smuggling is real but needs a specific upstream/downstream proxy mismatch. **B** — useful in a campaign, not a one-shot.
- **CVE-2022-42252** — also CWE-444 smuggling. **B.**
- **CVE-2021-25122** — "Exposure of Sensitive Information" (CWE-200). Cross-request response sharing under specific conditions. Mostly a tester's bug; in production it's a credential-leak risk. **C.**
- **CVE-2023-28709** — "Fix for CVE-2023-24998 was incomplete." Parent is DoS. **D.**
- **CVE-2023-34981** — "information leak" (CWE-732). **D.**
- **CVE-2025-53506, CVE-2025-52520, CVE-2025-48988, CVE-2024-34750, CVE-2025-48989, CVE-2023-24998, CVE-2019-0199** — DoS family (CWE-400, -770, -190, -404). **D.**
- **CVE-2022-45143, CVE-2026-34483** — JSON-error/access-log valve escaping bugs (CWE-116, CWE-74). Log injection at best. **D.**
- **CVE-2026-34487** — sensitive info into log file (CWE-532). **D.**
- **CVE-2026-29129** — cipher preference order not preserved (CWE-327). Crypto-config bug, no exploit primitive directly. **D.**
- **CVE-2024-22262, CVE-2026-24734** (the latter is Tomcat-side input validation generic; the former is misattributed in my own notes — actually spring-web; see below).
- **CVE-2019-17563** — session fixation, FORM auth (CWE-384). Narrow window per the summary. **C.**
- **CVE-2019-12418** — "Insufficiently Protected Credentials" (CWE-522). Local manager file readable. **C.**
- **CVE-2019-10072** — CWE-667 improper locking → DoS. **D.**
- **CVE-2018-8034** — host name verification missing (CWE-295). **C** — TLS MITM on a Tomcat *client* (HttpClient inside Tomcat). Active-network-attacker required.
- **CVE-2018-1336** — UTF-8 decoder overflow (CWE-835), DoS. **D.**
- **CVE-2018-1272** — "Possible privilege escalation" in spring-core, but listed under Tomcat in error? Actually mapped to spring-core in dataset. Covered in spring-core section.
- **CVE-2026-34487, CVE-2026-29129** already covered above.

---

## Spring Framework / spring-web / spring-webmvc / spring-core / spring-beans (individually tiered)

- **CVE-2022-22965** — Spring Framework "Remote Code Execution" (Spring4Shell-shape). CWE-94. Critical Spring MVC RCE via property-binding when the app has a specific WAR-deployment + JDK 9+ + spring-beans `ClassLoader` reach. The summary literally says "Remote Code Execution in Spring Framework" — direct primitive. Default-config-ish: hits a stock Spring MVC controller with a POJO param, but only on Tomcat WAR (not embedded jar). **Tier A** — almost S, but the WAR/JDK precondition is real.
- **CVE-2024-38816, CVE-2024-38819** — Spring Framework path traversal (CWE-22). On a functional web framework with static resource serving, path traversal in URL handler → arbitrary file read. Direct primitive, but only on apps using `RouterFunctions.resources()` or static-resource handlers in particular configurations. **Tier A** for -38819 (more general configs reachable per summary), **B** for -38816 (functional-router specific).
- **CVE-2020-5398** — RFD attack via Content-Disposition (CWE-494, CWE-79). RFD is a browser-victim chain — operator value is moderate; needs social engineering. **C.**
- **CVE-2023-20860** — security bypass via mvcRequestMatcher pattern mismatch. Auth-routing bypass primitive. The bug allows hitting endpoints meant to be protected by tricking the matcher. **A** — direct auth bypass with no exotic precondition; common and reachable on default Spring Security configs.
- **CVE-2023-34053** — DoS in Spring Framework. **D.**
- **CVE-2024-22262, CVE-2024-22259, CVE-2024-22243** — Spring URL parsing / open redirect / SSRF (CWE-601). Open redirect is C-tier on its own. SSRF in the request-validating component (-22243) is more useful — internal pivot. **B** for -22243, **C** for the redirects.
- **CVE-2022-22968** — case-sensitivity (CWE-178). Auth-condition bypass shape but the patch was tiny — likely Spring Data binding header trick. **C.**
- **CVE-2022-22970** — DoS in Spring Framework (CWE-770). **D.**
- **CVE-2024-22233** — DoS in spring-core. **D.**
- **CVE-2018-15756** — DoS in Spring Framework. **D.**
- **CVE-2018-1272, CVE-2018-1258** — privilege escalation / authorization bypass when Spring Framework + Spring Security used in a specific way. CWE-863 on -1258. The bug pattern: framework misroutes auth check. **B** — real auth bypass, but precondition is a non-trivial multipart-controller setup.
- **CVE-2025-41249** — annotation detection mechanism, improper authorization (CWE-285, CWE-863). Auth-decision bypass via annotation discovery edge case. **A** — modern, broad reach, direct auth-bypass primitive.

---

## spring-security cluster (12 events) — individually tiered

This is the trust-boundary cluster. By the NP rule we use, every spring-security CVE that affects the security-decision pipeline is NP. By exploit utility, many of them are still B because the precondition is "app uses the specific feature."

- **CVE-2022-22978** — Authorization bypass in Spring Security (CWE-285, CWE-863). Critical. Direct auth bypass with the well-known regex-anchor confusion: a path that looks protected isn't. Default Spring Security configurations using `RegexRequestMatcher` are reachable. **Tier A — leaning S.** Default-config × network-edge × direct primitive (full auth bypass on protected endpoints). The reason I don't give it outright S is that the matcher choice is application-defined, but the regex-confusion pattern is very common in real apps.
- **CVE-2025-41232** — Authorization bypass for method security on private methods (CWE-693). Modern, direct primitive: call a "protected" service method via reflection or a sibling-class call path and the `@PreAuthorize` doesn't fire. **Tier A.** Discovery-cost moderate but exploit ergonomics great once found.
- **CVE-2025-41248** — Annotation detection mechanism authorization bypass (CWE-289, CWE-863). Same shape as -41249 above. **Tier A.**
- **CVE-2024-38821** — Authorization bypass of static resources in WebFlux (CWE-285, CWE-770). Reach static resources that should be auth-gated. WebFlux is a minority deployment vs MVC, but for those that use it this is a direct read of protected files. **Tier A.**
- **CVE-2023-34034** — Access Control Bypass in Spring Security (CWE-281, CWE-284). Critical. Direct primitive. **A.**
- **CVE-2023-34035** — Misconfigured authorization rules with multiple servlets. Easier to spot in audit, harder to count on as a generic exploit. **B.**
- **CVE-2022-31692** — Auth bypass via forward/include dispatcher types (CWE-863). Critical. Send request, internal forward bypasses Security filter. **Tier A.**
- **CVE-2024-22234** — Broken Access Control with isFullyAuthenticated (CWE-284). Specific API misuse in apps. **B.**
- **CVE-2024-22257** — Erroneous authentication pass (CWE-287, CWE-862). The summary directly says "authentication pass" → token-acceptance bug. **A.**
- **CVE-2026-22732** — Spring Security HTTP headers not written under some conditions (CWE-425). "Direct request forgery" shape. Critical severity but the primitive is "headers (X-Frame-Options etc.) missing under condition X." That's a defense-in-depth weakening, not a direct primitive. **C** — CWE-425 oversells; severity score oversells more.
- **CVE-2021-22112** — privilege escalation in spring security (CWE-269). The CWE-269 label is generic; the actual primitive is "session retains privileged authority after a deauth event." **B** — real but needs application's auth flow to match.
- **CVE-2021-22119** — Resource Exhaustion (CWE-400, CWE-863). DoS-flavored auth bug. **C.**
- **CVE-2020-5407** — Signature wrapping (CWE-347). XML-signature wrapping in SAML-via-spring-security. Critical primitive (forge SAML assertion → admin) on apps using SAML. **A** for SAML deployments; **C** otherwise.
- **CVE-2019-11272** — Insufficiently protected credentials + improper auth (CWE-287, CWE-522). **B.**
- **CVE-2018-15801** — auth bypass (CWE-345). **B.**

---

## Spring Boot

- **CVE-2025-22235** — `EndpointRequest.to()` creates wrong matcher if actuator endpoint not exposed (CWE-20, CWE-862). Actuator endpoints exposed beyond the matcher's intent. The Spring Boot actuator suite includes `heapdump`, `env`, `mappings`, etc. — leaking memory dumps and config. Some actuators reach RCE through `jolokia` or `loggers`. **Tier A** — hidden-gem-ish: CWE-20 oversells generic input validation, but this is an actuator-exposure auth bypass with potential RCE via `jolokia`/`env`+JNDI.
- **CVE-2023-20883** — Spring Boot Welcome Page DoS. **D.**
- **CVE-2022-27772** — Temporary Directory Hijacking → LPE in spring-boot. CWE-377/379/668. **Local** privilege escalation. Not a remote primitive. **D** as remote operator. (Internal builder pivot only.)

---

## Apache Log4j (3 events)

- **CVE-2021-44228** — Log4j JNDI injection (CWE-20, CWE-400, CWE-502, CWE-917). Direct primitive: any log-message string containing `${jndi:ldap://...}` triggers an attacker-controlled class load. **Default-config × network-edge (any input that ends up in a log) × direct one-shot RCE.** This is the textbook S definition. **Tier S.** The CWE-20 tag undersells dramatically — the realistic primitive is unauthenticated remote class load via attacker-served LDAP.
- **CVE-2021-45046** — Incomplete fix for the above. Same primitive, same network shape, smaller payload variants. **Tier S** as the patch-bypass (operator: "if patch level is between the bad one and the good one, ship the same payload").
- **CVE-2021-45105** — Recursion DoS (CWE-20, CWE-674). Stack overflow via self-referential lookup. **D** as RCE-seeking operator.
- **CVE-2023-26464** — log4j 1.x DoS. **D.**

---

## Apache ActiveMQ (4 events)

- **CVE-2023-46604** — ActiveMQ RCE (CWE-502). The OpenWire protocol unmarshalling unauthenticated TCP traffic invokes constructors of attacker-named classes. **Default-config × network-edge × direct primitive.** Public TCP port (61616) exposed broadly because most operators don't realize OpenWire is a deserializer. **Tier S.**
- **CVE-2026-34197** — Authenticated ActiveMQ RCE via Jolokia MBeans (CWE-20). Authenticated. CWE-20 oversells. The primitive is "use Jolokia HTTP endpoint to invoke MBean operations including arbitrary code execution" — that's a strong primitive but auth-gated. **Tier A** — assume valid creds achievable via brute force or dev defaults.
- **CVE-2026-39304** — DoS via OOM. **D.**
- **CVE-2019-0222** — Code Injection in activemq-client (CWE-94). Client-side code injection? Probably "deserialize broker response → RCE" or "AMQP frame parsing." Either way it's a client-attack — needs an attacker-controlled broker. **C** — useful if you're the broker, not if you're the attacker reaching a target.
- **CVE-2018-11775** — Improper Certificate Validation (CWE-295) in activemq-client. **C** — TLS MITM on AMQ client connections.

---

## snakeyaml (2 events)

- **CVE-2022-1471** — SnakeYaml Constructor Deserialization RCE (CWE-20, CWE-502). Same shape as Jackson polymorphic typing — by default older SnakeYaml resolves YAML tags like `!!javax.script.ScriptEngineManager` into class instantiations. **Default-config × any-YAML-input × direct RCE.** Apps that take YAML over HTTP (Spring config endpoints, k8s-style configs, OpenAPI specs) are reachable. **Tier S** by mechanism. The reason I don't always tier this S is that YAML-over-HTTP is rarer than JSON-over-HTTP; on average call this **A**, and **S** if the manifest shows a Spring app exposing a YAML config endpoint.
- **CVE-2022-25857** — DoS (CWE-400, CWE-776) via uncontrolled resource consumption. **D.**

---

## Apache Commons (2 events)

- **CVE-2022-42889** — commons-text "Arbitrary code execution" (CWE-94). Looks structurally identical to log4shell: string interpolation lookup that resolves `${url:...}` → fetches code. The reachability depends on whether `StringSubstitutor` is used on attacker input — many apps use commons-text for templating. **Tier A** — primitive is sharp but reach is per-app, not per-classpath. Promote to **S** for any app that uses StringSubstitutor on user input by default.
- **CVE-2024-47554** — commons-io DoS via XmlStreamReader (CWE-400). **D.**

---

## Thymeleaf (2 events, both 2026-04-15)

- **CVE-2026-40477** — Improper restriction of accessible objects in Thymeleaf expressions (CWE-1336, CWE-917). Template-engine SSTI. SSTI in Thymeleaf reaches RCE through `T(java.lang.Runtime).getRuntime().exec(...)` if attacker controls part of a template expression. The precondition: app must render attacker-influenced data as a Thymeleaf expression (not as text content). **Tier A** — SSTI is a strong primitive when template injection is reachable; the question is whether the app passes user input into `th:text` (safe) vs into a template name or unsafe attribute (reachable).
- **CVE-2026-40478** — companion to above, "specific syntax patterns for unauthorized expressions." Same primitive class. **Tier A.**

---

## httpclient5 (1 event)

- **CVE-2025-27820** — Apache HttpClient disables domain checks (CWE-295). TLS hostname-validation bug → MITM if the attacker is on-path. **Tier C** — needs network position; primitive isn't direct on-target.

---

## logback (2 events)

- **CVE-2023-6378** — logback serialization (CWE-502). Logback's `SocketServer/ServerSocketReceiver` deserializes from a TCP socket. If the app exposes a logback receiver on a port (rare in production, common in dev/staging), unauth RCE. **Tier A** — direct primitive but precondition rare.
- **CVE-2023-6481** — DoS via poisoned data. **D.**

---

## PostgreSQL JDBC (5 events)

- **CVE-2024-1597** — pgjdbc SQL injection via line comment generation (CWE-89). SQLi inside the JDBC driver itself. Critical. Reachable only if the app passes user input through `PreparedStatement` parameters AND uses a specific question-mark-binding pattern with `simple` query mode AND has a numeric placeholder followed by attacker-controlled data. Precondition narrow but the primitive — driver-level SQLi — bypasses normal "we use prepared statements" defense. **Tier A** as a hidden gem; CWE-89 undersells nothing but the *location* (driver, not app code) is the trap.
- **CVE-2025-49146** — pgjdbc allows fallback to insecure auth despite `channelBinding=require` (CWE-287). Auth-step bypass — server-side attacker can force plaintext auth even when client demands binding. **Tier B** — needs a malicious or compromised PG server.
- **CVE-2022-31197** — pgjdbc SQL injection via column names in `ResultSet.refreshRow()` (CWE-89). Same family as -1597. **B** — preconditions narrower (refreshRow is uncommon).
- **CVE-2022-21724** — pgjdbc class instantiation when providing plugin classes (CWE-665, -668, -74). JDBC URL parameter abuse — attacker who controls the JDBC URL can load arbitrary classes. Real primitive when the URL is attacker-influenced (rare, but legacy "build connection string from input" patterns exist). **B.**
- **CVE-2020-13692** — XXE in pgjdbc (CWE-611). XXE in driver responses — needs malicious server. **C.**

---

## Per-event tier list — full summary

### TIER S (5 unique entries)
- **CVE-2021-44228** (log4j-core) — Log4Shell-class JNDI lookup, any logged input.
- **CVE-2021-45046** (log4j-core) — patch-bypass twin of the above.
- **CVE-2023-46604** (activemq) — unauth deserialization on OpenWire TCP.
- **CVE-2021-39144** (xstream) — unauth deserialization (CWE-306) without allowlist.
- **CVE-2022-1471** (snakeyaml) — default unsafe YAML constructor (S when YAML-over-HTTP reachable, otherwise A).

### TIER A (heavy weaponization candidates)
- **CVE-2022-22965** (spring-web/-beans) — Spring property-binding RCE.
- **CVE-2025-24813** (tomcat) — partial-PUT RCE chain.
- **CVE-2020-1938** (tomcat) — AJP arbitrary-file/RCE (CWE-269 mislabel; real primitive is AJP handler abuse).
- **CVE-2026-29145** (tomcat) — CLIENT_CERT auth bypass.
- **CVE-2026-34197** (activemq) — authenticated Jolokia MBean RCE.
- **CVE-2024-38819** (spring-webmvc) — path traversal.
- **CVE-2023-20860** (spring-webmvc) — auth bypass via mvcRequestMatcher mismatch.
- **CVE-2025-22235** (spring-boot) — actuator endpoint exposure (gem).
- **CVE-2025-41249, CVE-2025-41248, CVE-2025-41232** (spring) — annotation/method-security auth bypasses.
- **CVE-2022-22978** (spring-security) — regex-anchor auth bypass (near-S).
- **CVE-2024-38821** (spring-security) — WebFlux static-resource auth bypass.
- **CVE-2023-34034** (spring-security) — access control bypass.
- **CVE-2022-31692** (spring-security) — forward/include dispatch auth bypass.
- **CVE-2024-22257** (spring-security) — erroneous auth pass.
- **CVE-2020-5407** (spring-security) — XML signature wrapping (SAML).
- **CVE-2026-40477, CVE-2026-40478** (thymeleaf) — SSTI primitives.
- **CVE-2022-42889** (commons-text) — string-interpolation RCE.
- **CVE-2023-6378** (logback) — socket-receiver deserialization.
- **CVE-2024-1597** (pgjdbc) — driver-level SQLi (gem).
- **XStream cluster (most members)** — A as a cluster.
- **Jackson cluster gadgets reachable without `enableDefaultTyping`** (subset of cluster) — A.

### TIER B
- **CVE-2025-55752** (tomcat path traversal).
- **CVE-2021-25329** (tomcat session-persistence RCE — needs writable store).
- **CVE-2019-0232** (tomcat CGI Windows RCE).
- **CVE-2018-8014** (tomcat CORS supportsCredentials).
- **CVE-2023-46589, CVE-2022-42252** (tomcat smuggling).
- **CVE-2024-56337, CVE-2024-50379** (tomcat TOCTOU).
- **CVE-2024-22243** (spring-web SSRF).
- **CVE-2018-1272, CVE-2018-1258** (spring auth-bypass).
- **CVE-2024-38816** (spring-webmvc functional-router path traversal).
- **CVE-2023-34035** (spring-security multi-servlet misconfig).
- **CVE-2024-22234** (spring-security isFullyAuthenticated misuse).
- **CVE-2021-22112** (spring-security session-priv carry).
- **CVE-2019-11272, CVE-2018-15801** (spring-security creds/auth).
- **CVE-2025-49146** (pgjdbc channel-binding fallback).
- **CVE-2022-31197, CVE-2022-21724** (pgjdbc).
- **CVE-2020-25649** (jackson XXE — own primitive class).
- **CVE-2018-14720, -14721, -19362** (jackson XXE/SSRF).
- **Jackson cluster as cluster default.**
- **XStream SSRF members (-39150, -39152).**

### TIER C
- **CVE-2024-22262, CVE-2024-22259** (spring-web open redirect).
- **CVE-2022-22968** (spring case-sensitivity).
- **CVE-2020-5398** (spring RFD — needs social).
- **CVE-2026-22732** (spring-security headers — CWE-425 oversells).
- **CVE-2021-22119** (spring-security DoS-flavored auth).
- **CVE-2021-25122** (tomcat info exposure).
- **CVE-2019-17563** (tomcat session fixation).
- **CVE-2019-12418** (tomcat creds).
- **CVE-2018-8034** (tomcat hostname verification — MITM).
- **CVE-2025-27820** (httpclient5 hostname).
- **CVE-2018-11775** (activemq-client cert).
- **CVE-2019-0222** (activemq-client code injection, broker-side).
- **CVE-2020-13692** (pgjdbc XXE).
- **Jackson info-disclosure outliers (CVE-2019-12086, -14892, -14893).**

### TIER D
- **All DoS-only events:** CVE-2026-39304, -34483, -34487, -29129; CVE-2025-53506, -52520, -48989, -48988, -52999; CVE-2024-34750, -47554; CVE-2023-46589 (when DoS-only reading), -34053, -28709, -34981, -24998, -26464, -6481; CVE-2022-45143, -42252, -42003, -42004, -25857, -22970, -22968 (case-sensitivity, marginal), -41966, -40151, -36518; CVE-2021-46877, -45105, -43859, -25122, -21341, -22119; CVE-2020-25657, -10968 (just nested-object DoS subset of jackson cluster), -36518; CVE-2019-0199, -10072, -16335 (DoS subset), CVE-2018-15756, -1336.
- **Local-only:** CVE-2022-27772 (spring-boot temp-dir LPE).
- **Log injection / config disclosure / weak crypto config:** CVE-2026-29129, -34483, -34487, -1336.
- **Jackson DoS bracket of cluster** (CVE-2020-36518, CVE-2025-52999, CVE-2022-42003, -42004, -46877, -36518).
- **XStream DoS bracket of cluster** (CVE-2024-47072, CVE-2022-40151, -41966, CVE-2021-43859, -21341).

*(Some D entries are listed multiple times because they can be classified by primitive or by the cluster they came from. Counted once each in the totals below.)*

---

## Summary deliverables

### 1. Tier counts (cluster-aware)

Treating Jackson as 1 cluster entry and XStream as 1 cluster entry (with promoted/demoted single-CVE outliers counted separately):

| Tier | Count | Details |
|------|-------|---------|
| **S** | **5** | log4j-44228, log4j-45046, activemq-46604, xstream-39144, snakeyaml-1471 |
| **A** | **22** | spring4shell-22965, tomcat-24813, tomcat-1938, tomcat-29145, activemq-34197, spring-mvc-38819, spring-mvc-20860, spring-boot-22235, spring-41249, spring-sec-41248, spring-sec-41232, spring-sec-22978, spring-sec-38821, spring-sec-34034, spring-sec-31692, spring-sec-22257, spring-sec-5407, thymeleaf-40477, thymeleaf-40478, commons-text-42889, logback-6378, pgjdbc-1597, **plus XStream cluster as A**, **plus Jackson reachable-without-default-typing subset as A** |
| **B** | **~26** | (events + Jackson cluster default + XStream SSRF outliers) |
| **C** | **~16** | |
| **D** | **~32 individual + Jackson DoS-bracket + XStream DoS-bracket** | |

If we expand the clusters (Jackson 64 + XStream 21 fully tier-listed individually), the raw counts are roughly: S=5, A=30, B=80, C=20, D=40. The cluster-aware view is the operationally honest one — I'd treat Jackson as one decision and XStream as one decision, with three or four interesting outliers each.

### 2. Top weaponization picks (ordered)

1. **CVE-2021-44228** — Log4Shell. Single-shot, network-edge, default-config in any app that logs HTTP headers.
2. **CVE-2023-46604** — ActiveMQ OpenWire unauth deser RCE. Public-facing port, no auth, deterministic gadget.
3. **CVE-2021-45046** — Log4Shell patch-bypass; same payload class, complementary version coverage.
4. **CVE-2021-39144** — XStream unauth (CWE-306) deser RCE — the one cluster entry that doesn't need extra precondition discovery.
5. **CVE-2022-1471** — SnakeYaml, when YAML-over-HTTP is reachable.
6. **CVE-2022-22965** — Spring4Shell. Real RCE on real apps; my campaign would lead with this against any WAR-deployed Spring on JDK 9+.
7. **CVE-2025-24813** — Tomcat partial PUT RCE on misconfigured `readonly=false` deployments.
8. **CVE-2022-22978** — Spring Security regex-anchor auth bypass; a near-universal pattern in real apps.
9. **CVE-2020-1938** — Tomcat AJP. CWE-269 hides this one but I'd build the chain for any internal-network engagement.
10. **CVE-2024-1597** — pgjdbc driver-level SQLi. Hidden gem; bypasses "we use prepared statements" assumption.

### 3. Trap picks (CWE oversells)

- **CVE-2026-22732** (CWE-425, "Direct Request Forgery"). Critical severity, scary-sounding CWE. Real primitive: "X-Frame-Options sometimes missing." Defense-in-depth only. **Tier C.**
- **CVE-2026-29129** (CWE-327, "Inadequate Encryption Strength"). Real primitive: configured cipher *preference* not preserved — TLS still negotiates an acceptable cipher. **Tier D.**
- **CVE-2018-1336** (CWE-835, infinite loop in UTF-8 decoder). DoS only. **Tier D.**
- **CVE-2018-8014** (CWE-1188, insecure default initialization). Sounds critical. Reality: CORS filter, when the operator opts into it, has bad defaults. Three layers of "if". **Tier B at best, often C.**
- **CVE-2021-22119** (CWE-400 + CWE-863, "Resource Exhaustion in Spring Security"). The CWE-863 is bait — it's not an authorization bypass, it's DoS in an auth code path. **Tier C.**
- **The entire Jackson DoS bracket** (CWE-502 + CWE-400): nine CVEs that look like deserialization gadgets but are actually "feed me deeply nested JSON and I'll OOM." CWE-502 is a trap label here; a careful operator notices the co-tag of CWE-400 and the absence of any "RCE" or "code execution" word in the summary. **Tier D each.**
- **The XStream DoS bracket** — same trap, CWE-502 label hiding stack-overflow primitive. **Tier D each.**

### 4. Hidden-gem picks (CWE undersells) — the safety-net candidates

These are exactly what this round is testing. Events where the CWE label is generic or weak but the actual primitive is sharp.

- **CVE-2020-1938** (CWE-269 alone). "Improper Privilege Management" sounds like a local LPE. The bug is the AJP protocol handler reading file contents over network port 8009 with no auth, and chaining to RCE if the attacker can write a JSP and induce its inclusion. CWE-269 undersells *catastrophically*. **Tier A** for safety-net purposes.
- **CVE-2025-24813** (CWE-44 + CWE-502). "Path Equivalence" + "Deserialization" — the CWE-44 undersells; the CWE-502 oversells (it's not arbitrary deser, it's the chained gadget at the end of a partial-PUT primitive). The realistic primitive is "PUT a session file, GET a different session ID, the server reads the PUT file as your session and deserializes the embedded gadget." **Tier A.**
- **CVE-2024-1597** (CWE-89 only). Looks like generic SQLi until you notice it's a *driver-level* SQLi: it bypasses the entire "we parameterize all queries" defense. **Tier A.**
- **CVE-2025-22235** (CWE-20 + CWE-862). "Improper input validation" plus "missing authorization." Both labels weak. Reality: Spring Boot actuator authorization bypass — `heapdump`, `env`, `loggers`, `jolokia` reachable without auth in some configurations. The `loggers` actuator alone can change logging config to leak sensitive data; `jolokia` reaches MBean RCE. **Tier A.**
- **CVE-2022-22978** (CWE-285 + CWE-863). The label is right but the *frequency* is undersold — this is a default-pattern bug that probably breaks 30% of real-world Spring Security configs. **Tier A — leaning S.**
- **CVE-2025-41232** (CWE-693, "Protection Mechanism Failure"). Generic CWE. Reality: the entire `@PreAuthorize`/`@Secured` annotation system fails for private methods, which means refactor-introduced auth holes ship to prod silently. **Tier A.**
- **CVE-2026-29145** (CWE-287). Label is right; the gem is "CLIENT_CERT in Tomcat" is more common than people think in regulated industries (banks, gov, healthcare) — these are exactly the targets where mTLS auth bypass is highest-value. Tier A is right; the safety-net angle is that operators not familiar with mTLS deployments may pass on this when they shouldn't.
- **CVE-2022-22965** (CWE-94 + CWE-74). Both right but generic. The trap is in the *opposite* direction of the prior entries — this one's mostly correctly labeled but the fame ("Spring4Shell") may bias an analyst-not-in-character to overweight. As an operator I'd take this regardless.
- **CVE-2021-39144** (CWE-306 alongside CWE-502/CWE-94). The CWE-306 is the gem signal — when a deserialization CVE is co-tagged with "Missing Authentication," that's the operator's flag for **S**.

The cross-cutting hidden-gem rule for safety-net purposes: **a deserialization or RCE-class CVE co-tagged with CWE-306, CWE-862, CWE-285, or CWE-287 is more dangerous than the same primitive without the auth-missing co-tag.** The auth-missing label is what turns a B-tier "sometimes-reachable" into an S/A "always-reachable."

### 5. CWE-502 (deserialization) as a category — within-category discriminator

The dataset is roughly 50% CWE-502 (Jackson 64, XStream 21, plus log4j 2, ActiveMQ 1, snakeyaml 1, logback 1, Tomcat 1, plus DoS impostors). Should ALL deser bugs be high-tier?

**No. The within-CWE-502 discriminator is the same as the cross-cluster discriminator: default-config × network-edge × direct primitive.**

- **Default-config = "no special flag needed."** XStream pre-1.4.18 was unsafe by default. SnakeYaml's default constructor was unsafe until 2.0. ActiveMQ OpenWire was unsafe by default. Log4j JNDI lookup was on by default. Jackson's polymorphic typing was *off* by default — that's why the Jackson cluster is collectively B and individual XStream entries are A.
- **Network-edge = "reachable via standard request."** Log4j: any HTTP header that gets logged. ActiveMQ: TCP 61616. XStream: any `application/xml` POST body in an XStream-using app. Logback: TCP socket if the receiver is enabled (rare). Tomcat session deser: requires writable persistence (rare). Driver-level (pgjdbc XXE): requires malicious server (rarer still).
- **Direct primitive = "one-shot RCE, no chain."** Most CWE-502 RCEs are one-shot once the gate is open. The DoS impostors fail this test entirely.

Applied to the dataset:
- All three gates open: log4j-44228/45046, activemq-46604, snakeyaml-1471 (when YAML-over-HTTP), xstream-39144 → **S**.
- Two gates open: bulk XStream, jackson-when-default-typing-on, logback-socket → **A**.
- One gate open or chain-only: Jackson default, jackson XXE/SSRF, tomcat session-deser, pgjdbc class instantiation → **B**.
- All gates closed: any "deser" tag co-occurring with "DoS" or with no RCE language in the summary → **D**.

The category-level rule fails: not all deser is equal. The operator's gate test (default × edge × direct) carries through correctly inside CWE-502.

### 6. Cross-cluster pattern — package-level heuristics

**"Every CVE is high-priority" packages** — i.e., when this package shows in the manifest, assume the operator should triage every entry:
- **log4j-core** — small CVE volume, every RCE-tagged one is or could be Log4Shell-class.
- **activemq-broker / activemq-client** — same: when broker-side, RCE-class. Client-side bugs are weaker but the broker-side ones are S.
- **snakeyaml** (RCE bracket only).
- **commons-text** (single CVE here, but it's the structural Log4Shell of the package).

**"Most CVEs need preconditions you'll never find"** — high CVE volume, individually low base rate:
- **jackson-databind** — 64 CVEs, all gated by default-typing.
- **xstream** — 21 CVEs, gated by allowlist absence; better operator yield than Jackson because the gate is open more often pre-1.4.18.
- **tomcat-embed-core** — 29 CVEs, mostly DoS or narrow-config primitives. The two that matter (24813, 1938) are gated by non-default deployment shapes.
- **pgjdbc** — 5 CVEs, all gated by either driver-control or specific URL patterns.

**"Internal-only / dependency-only" packages** — exploitation requires position the operator may not have:
- **logback** — useful only when socket receiver is enabled (rare in prod).
- **activemq-client** — useful only when attacker is the broker.
- **httpclient5** — useful only when attacker is on-path.
- **commons-io** — DoS only.

**"Trust-boundary, complexity-driven"** — spring-security has 12 entries. Each is reachable when the app uses the specific feature. Operator approach: assume every spring-security CVE in the recent (2022+) bracket is likely to land somewhere; older ones less so. Authorization-bypass CWEs (-863, -285) carry the real signal.

### 7. The discriminator check — does (default-config × network-edge × primitive-direct) hold?

**S-tier picks (5):**
- log4j-44228: default-config (lookups on), network-edge (HTTP-logged), direct (one-shot RCE). **Pass all three.** ✓
- log4j-45046: same. **Pass all three.** ✓
- activemq-46604: default-config (OpenWire unsafe), network-edge (TCP 61616), direct (gadget). **Pass all three.** ✓
- xstream-39144: default-config (no allowlist + CWE-306 confirms unauth), network-edge (XML POST), direct (gadget). **Pass all three.** ✓
- snakeyaml-1471: default-config (unsafe constructor), edge IF YAML-over-HTTP, direct. **Passes 2.5 of 3** — the YAML-edge condition is per-deployment, which is why I'd downgrade to A for an arbitrary target with no manifest evidence of YAML-over-HTTP. *Fair callout that this S is conditional.*

**A-tier picks — discriminator check on a sample:**
- **CVE-2022-22965** (Spring4Shell): default-config-ish (works on stock controllers), edge yes, direct yes. **Loses 0.5 on default-config** — needs WAR + JDK 9+. That's why A not S.
- **CVE-2025-24813** (Tomcat partial PUT): NOT default-config (`readonly=true` is default), edge yes, direct yes. **Loses 1.** Correctly A.
- **CVE-2020-1938** (AJP): default-config historically yes (port 8009 default-on), edge yes (port 8009 sometimes firewalled), direct (file-read; RCE chain). **Mixed on edge** for internet-facing but solid for internal. A is right.
- **CVE-2025-22235** (actuator misconfig): NOT default-config (depends on which actuators are exposed), edge yes, direct yes (heapdump → secrets → RCE chain). **Loses 1.** A.
- **CVE-2022-22978** (regex auth bypass): default-config (RegexRequestMatcher pattern is per-app but the bug class is default), edge yes, direct yes. **Passes all three** in my judgment, which is why I tagged it "leaning S." This is the closest call in the A bracket.
- **CVE-2024-1597** (pgjdbc SQLi): default-config (driver default), edge no — needs SQLi reach in the app first, so really chain-into-existing-SQLi-surface. **Loses 1.** A is right; the safety-net angle is "operator might tier this lower because it's a driver bug."

**Events that pass all three but I tier lower (conscious downgrade):**
- **CVE-2022-22978** — passes all three, tagged A "leaning S." Promote? Yes, on reflection — a working operator with the regex-anchor playbook would treat any Spring Security-using app as a probable hit. **Treat as S in practice.**
- **CVE-2021-39144** is already S. No others in this set pass all three.

**Events that fail all three but I tier higher (conscious upgrade):**
- None in the S/A bracket. The C-tier MITM bugs fail all three and are correctly C.

**Discriminator integrity:** The default × edge × direct test holds up. The one place it shows strain is where "default-config" is application-defined rather than library-defined (e.g., spring-security regex matchers). For application-defined defaults, the operator has to substitute statistical confidence ("most apps configure this way") for library-level certainty. That's an additional uncertainty source the discriminator doesn't model cleanly.

---

## Closing operator note on the safety-net question

The exercise is "do my tiers backstop the NP+DI filter for events the filter rejects." Without seeing the filter labels, my best inference of likely NP+DI rejections that I tier high anyway:

1. **CVE-2020-1938** (AJP). NP+DI may reject because the CWE is CWE-269 (privilege management) — generic, not a parser/auth tag. I tier **A**. **Backstop.**
2. **CVE-2024-1597** (pgjdbc SQLi). pgjdbc may not register as NP under a strict "HTTP parser" reading. I tier **A**. **Backstop.**
3. **CVE-2025-22235** (Spring Boot actuator). CWE-20 + CWE-862 — the CWE-862 is auth-missing but the package is spring-boot core, not a parser. I tier **A**. **Backstop.**
4. **CVE-2025-24813** (Tomcat partial PUT). Tomcat is NP, but if the filter cares about CWE-44 ("Path Equivalence") it may downweight; the CWE-502 tag should save it. I tier **A**. **Probably caught, possibly backstop.**
5. **CVE-2026-40477, -40478** (Thymeleaf SSTI). Thymeleaf is NP-by-trust-boundary in the doc canon. I tier **A**. Caught.
6. **CVE-2022-42889** (commons-text). commons-text is utility, not parser; NP/DI may reject. I tier **A**. **Backstop.**
7. **CVE-2023-6378** (logback socket-deser). NP rejection likely (logging library), CWE-502 may flag DI. I tier **A** (with rare-precondition caveat). **Backstop, but real exploitation rare.**
8. **The XStream cluster, including -39144.** NP+DI likely catches XStream as a deserializer. Caught.
9. **Spring Security auth-bypass cluster.** NP-by-trust-boundary in the doc canon. Caught.
10. **Jackson cluster.** NP+DI catches the package; depends on whether the filter tracks individual CVEs or treats package as a whole. Caught at package level.

The places I'm worried the NP+DI filter would miss are the operator-promoted gems: AJP, pgjdbc-driver-SQLi, Boot-actuator, commons-text, logback-socket. If those events were exploited in the wild and the filter rejected them, my tiers would have caught at least four of the six suspected backstop opportunities at A or above.

That's what the test is asking. My tiers don't demand the NP+DI filter expand its own labels — they just need to flag the same vulnerability the filter rejected. On the events I expect to be the operational holes, the tier-A-or-higher safety net holds.

---
