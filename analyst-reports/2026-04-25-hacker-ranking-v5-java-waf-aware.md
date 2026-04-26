# Hacker Ranking v5 — 175-event Spring/Java Manifest with WAF-defensibility Axis

**Operator framing.** Same dataset as R3. Same primitive-first reasoning. New axis: WAF-defensibility. Two campaigns exist now, not one — the "WAF-friendly" campaign is a sprint (ship before Cloudflare/AWS-WAF/Akamai push emergency rules), the "WAF-hostile" campaign is a marathon (no perimeter control will close the window before patch deploys, which is weeks). The four-axis discriminator is:

1. **Default-config reachability** — vulnerable code path on a stock install.
2. **Network-edge exposure** — attacker bytes reach the sink from outside the perimeter.
3. **Primitive directness** — one-shot RCE / full auth bypass, no chain.
4. **WAF-defensibility complexity** — emergency WAF rule cannot meaningfully close the window. Wrong protocol, file-format parsing, looks-legitimate auth-flow input.

Tier mapping (R5):

- **S** — hits all 4. Defender has no perimeter control AND a working primitive AND default reach. Drop everything.
- **A** — hits 3 of 4. Includes "primitive A but WAF-friendly" (sprint window) and "WAF-hostile but lacks default-config" (long window per applicable target).
- **B** — hits 2 of 4 OR chain-only.
- **C** — hits 1 OR fundamentally weak primitive.
- **D** — DoS-only / unweaponizable.

WAF-axis vocabulary used below:

- **WAF-FRIENDLY** = signature-able payload, generic OWASP rules cover, emergency rule ships within hours.
- **WAF-MEDIUM** = signature exists but evadable (encoding, gadget obfuscation, format support gaps).
- **WAF-HOSTILE** = wrong protocol entirely, file-format parsing in body, or attack indistinguishable from legitimate traffic.

---

## Cluster: jackson-databind polymorphic-typing gadget chain (64 events)

**WAF call: WAF-MEDIUM (cluster).** Jackson gadget payloads carry well-known class names — `org.springframework.aop.config.MethodLocatingFactoryBean`, `com.sun.rowset.JdbcRowSetImpl`, `c3p0.JndiRefForwardingDataSource`, `org.apache.xalan.xsltc.trax.TemplatesImpl` — and emergency WAF rules can match on those strings inside a JSON body. But the body is JSON-decoded, optionally base64'd inside a field, optionally Unicode-escaped, and the gadget classpath shifts year-to-year. Defense-in-depth WAFs catch the public PoCs; novel obfuscation passes for weeks. Net: medium.

**Cluster verdict (R5): B as cluster, A for the default-typing-on subset, D for DoS impostors.** Same as R3. WAF-medium does not push the cluster up because the default-typing gate is the bigger filter (most modern Spring apps don't expose `Object`-typed fields to JSON deserialization at all). The WAF status doesn't materially shift the operator's economics on this cluster.

**A subset (default-typing-on or polymorphic-Map-field-on-classpath) — 50+ entries:** CVE-2017-7525 family — CVE-2018-7489, -11307, -12022, -12023, -14718, -14719, -19360, -19361; CVE-2019-12086, -14379, -14439, -14540, -14893, -16335, -16942, -16943, -17267 (CRITICAL), -17531, -20330; CVE-2020-8840, -9546, -9547, -9548, -10672, -10673, -10968, -10969, -11111, -11112, -11113, -11619, -11620, -14060, -14061, -14062, -14195, -24616, -24750, -35490, -35491, -35728, -36179, -36180, -36181, -36182, -36183, -36184, -36185, -36186, -36187, -36188, -36189; CVE-2021-20190; plus information-disclosure CVE-2018-5968, CVE-2019-14892. **Tier B as cluster, A if default-typing-on is confirmed.** WAF-medium leaves the cluster where it is.

**XXE / SSRF outliers:**
- **CVE-2020-25649** (XXE in Jackson via XmlMapper) — file read / SSRF. **WAF-MEDIUM.** XXE payload (`<!DOCTYPE>` with external entity) has signatures, but XML inside JSON contexts and the wide variety of XmlMapper config bypasses give attacker evasion room. **B.**
- **CVE-2018-14720** (XXE) — same shape, **WAF-MEDIUM, B.**
- **CVE-2018-14721** (SSRF in jackson-databind, CWE-918) — **WAF-MEDIUM.** SSRF probes have URL-shape signatures but the vector is "send a JSON body that contains a URL that the server fetches" — looks legitimate to a WAF that doesn't know which fields are URL-typed. **B.**
- **CVE-2018-19362** — Deserialization, **WAF-MEDIUM, B with cluster.**

**DoS outliers (downgrade to D):** CVE-2020-36518, CVE-2022-42003, CVE-2022-42004, CVE-2021-46877, CVE-2025-52999 (jackson-core stack overflow). **WAF status irrelevant — DoS is not the operator's primitive.** **D.**

**Net (R5 vs R3):** Cluster stays B. No tier shifts from WAF. Default-typing-on subset stays A.

---

## Cluster: XStream (21 events)

**WAF call: WAF-MEDIUM (cluster).** XStream's payload is XML with a class-naming attribute (`<map><entry><java.lang.Class>...`) — those class names are signature-able (Cloudflare ships rules within a day for known XStream gadgets). But XStream supports rare encodings (CDATA, processing instructions) and the gadget zoo is wider than Jackson's. Medium pushes the cluster up only marginally.

**Cluster verdict (R5): A as cluster, S for CVE-2021-39144.** Same as R3. Reason the cluster doesn't drop on WAF-medium: XStream's default-config-unsafe property is the primary gate, not WAF. Pre-1.4.18 XStream is unsafe by default — no `enableDefaultTyping`-equivalent needed. The operator wants this cluster regardless of WAF status.

**A entries:** CVE-2019-10173 (CRITICAL — old, unsafe-default era), CVE-2020-26217 (CWE-78 — pre-baked OS-command gadget — but **WAF-FRIENDLY-MEDIUM** because `Runtime.exec` patterns get matched), CVE-2021-29505 (CWE-94 RCE), CVE-2021-39139, -39141, -39145, -39146, -39147, -39148, -39149, -39151, -39153, -39154 (allowlist bypasses — WAF-MEDIUM, defense lags by gadget). **A each.**

**S entry — CVE-2021-39144.** CWE-306 (missing auth) co-tag is the operator's tell: deserialization reachable without auth. **WAF-MEDIUM** — class-name signature is evadable. Hits default-config + edge + direct + WAF-medium. **S** stands. (If WAF were FRIENDLY this would arguably drop to A, but it's MEDIUM at best.)

**SSRF outliers:** CVE-2021-39150, -39152 (CWE-918). SSRF is per-target value not RCE-direct. **WAF-MEDIUM.** **B each.**

**DoS outliers (D):** CVE-2024-47072, CVE-2022-40151, CVE-2022-41966, CVE-2021-43859, CVE-2021-21341. **D each.** WAF irrelevant.

**Net (R5 vs R3):** Cluster stays A. CVE-2021-39144 stays S. No movement.

---

## Apache Tomcat (31 events) — individually tiered

This cluster is where R5 makes the most movement vs R3. Tomcat has both HTTP-on-the-wire bugs (WAF-FRIENDLY/MEDIUM) and protocol-shift bugs (WAF-HOSTILE — AJP, smuggling, CGI, mTLS). The R5 axis matters here.

- **CVE-2025-24813** (CWE-44 + CWE-502, partial PUT RCE). HTTP `PUT` then `GET` chain with deserialization gadget at end. **WAF-MEDIUM.** PUT to a non-GET endpoint plus subsequent session-ID twiddle has a recognizable shape but it's distributed across two unrelated requests; emergency rule-writers struggle. Hits edge + direct + WAF-medium-leaning-hostile, loses default-config (`readonly=true` is default). **R5: A** (same as R3). I don't promote because the precondition is real.

- **CVE-2020-1938** (CWE-269, AJP "Ghostcat"). **WAF-HOSTILE.** AJP is a *binary protocol on port 8009 that the WAF does not see at all.* This is the canonical wrong-protocol case. Hits default-config (port 8009 was on by default for years), edge (when 8009 is reachable), direct (file-read → JSP-include chain), AND WAF-hostile. **R5: promote to S for any operator with internal-network reach; A for pure internet-edge.** R3 had this at A. The WAF axis is decisive: if 8009 is exposed, defenders have ZERO perimeter visibility. **Up-tier vs R3.**

- **CVE-2025-55752** (CWE-23, relative path traversal). HTTP path-traversal payload. **WAF-FRIENDLY.** `../` patterns and percent-encoded variants are the most signature-rich primitive in the OWASP CRS. Cloudflare ships within hours. **R5: B** (same as R3). The WAF window for an HTTP traversal bug is days, not weeks; doesn't change the tier but caps the campaign window.

- **CVE-2026-29145** (CWE-287, CLIENT_CERT auth doesn't fail). **WAF-HOSTILE.** mTLS handshake happens at the TLS layer; the WAF sits behind TLS termination and never sees the cert-validation flow. Even if the WAF terminates TLS, the bug is "auth incorrectly passes" — looks-legitimate flow. Hits edge + direct + WAF-hostile, loses pure default-config (mTLS deployment is per-app). **R5: A** (same as R3). I don't promote to S because mTLS is minority surface, but I bracket it more aggressively than R3 — for any regulated-industry target (banks, gov, healthcare) where mTLS is normal, treat as **S in those contexts**.

- **CVE-2021-25329** (CWE-502, follow-on to session-persistence RCE). Same chain mechanics as -24813, requires writable persistence. **WAF-MEDIUM.** **R5: B** (same as R3).

- **CVE-2019-0232** (CWE-78, OS command injection on Windows CGI). **WAF-FRIENDLY.** CGI command-injection payloads (`|`, `&`, backticks in query) are CRS-1 signature territory. Plus Windows-only and CGI-disabled-by-default. **R5: B** (same as R3). WAF closes the window fast on top of the narrow precondition.

- **CVE-2018-8014** (CWE-1188, CORS supportsCredentials default). **WAF-HOSTILE for the primitive class.** CORS misconfig is a browser-level cross-origin trust thing — there's no payload, just an `Origin` header that the WAF would normalize-or-pass-through. But the primitive itself is weak (chained ride-the-victim). Hits edge + WAF-hostile, loses default (CORS filter is opt-in) and direct (chain). **R5: B** (same as R3). WAF axis doesn't help because the primitive is fundamentally indirect.

- **CVE-2024-56337, CVE-2024-50379** (CWE-367, TOCTOU race). File-write then JSP-include race on case-insensitive FS. **WAF-MEDIUM.** Upload payloads (`.JSP`/`.jsp` case race) have signatures but are evadable. **R5: B** (R3 had C; **up-tier slightly to B** because the primitive's WAF-medium status combined with case-insensitive Windows-default deployments means this lands more often than C suggested). **Up-tier vs R3.**

- **CVE-2023-46589** (CWE-444, request smuggling). **WAF-HOSTILE.** Request smuggling is THE canonical WAF-bypass primitive — by definition the WAF and origin disagree on request boundaries, which means the WAF sees one request and the origin sees a smuggled second. The WAF cannot reliably block what it cannot parse correctly. Hits edge + direct (sometimes; depends on smuggled payload) + WAF-hostile, loses default-config (needs specific upstream/downstream shape). **R5: A** (R3 had B). **Up-tier vs R3.** Smuggling is exactly the bug class WAF axis is designed to elevate.

- **CVE-2022-42252** (CWE-444, smuggling via Content-Length). **WAF-HOSTILE.** Same logic as above. **R5: A** (R3 had B). **Up-tier vs R3.**

- **CVE-2021-25122** (CWE-200, cross-request response sharing). Information leak. **WAF-FRIENDLY-MEDIUM.** Even a careful WAF sees responses but can't easily detect "response went to wrong client" at the perimeter. The primitive is weak though. **R5: C** (same as R3).

- **CVE-2023-28709** — DoS follow-on. **D.**
- **CVE-2023-34981** — info leak. **D.**
- **CVE-2025-53506, CVE-2025-52520, CVE-2025-48988, CVE-2025-48989, CVE-2024-34750, CVE-2023-24998, CVE-2019-0199, CVE-2019-10072, CVE-2018-1336** — DoS family (CWE-400, -770, -190, -404, -667, -835). **D each.**
- **CVE-2022-45143, CVE-2026-34483, CVE-2026-34487** — log-valve / log-injection / sensitive-info-in-log. **D each.**
- **CVE-2026-29129** — cipher preference order. **D.** WAF irrelevant; not exploitable directly.
- **CVE-2026-24734** — CWE-20 generic input validation. Summary doesn't claim RCE or auth bypass; treat as configuration/parsing edge case. **C.**
- **CVE-2019-17563** (session fixation in FORM auth). Auth-flow looks-legitimate. **WAF-HOSTILE.** Loses default + direct (narrow window per summary). **R5: C** (same as R3). WAF axis acknowledged but precondition rules.
- **CVE-2019-12418** (CWE-522, local manager creds readable). Local-only. **C.**
- **CVE-2018-8034** (CWE-295, hostname verification missing). MITM. **C.**

---

## Spring Framework / spring-web / spring-webmvc / spring-core / spring-beans

- **CVE-2022-22965** (Spring4Shell, CWE-94/-74). **WAF-FRIENDLY.** The signature `class.module.classLoader` (and variants like `class['module']['classLoader']`) is the most-deployed emergency WAF rule of 2022. Cloudflare/AWS-WAF/Akamai shipped same-day. The precondition (WAR + JDK 9+) plus the FRIENDLY WAF status means: hits default + edge + direct + WAF-FRIENDLY (3 of 4). **R5: A** (same as R3). I considered down-tiering to B because the WAF closes the window so aggressively, but the bug class re-emerges with bypass payloads (Unicode escapes for `class`, alternate property names) and the WAR-deployed Spring estate is large enough that the sprint window matters. **Stay at A.**

- **CVE-2024-38819** (CWE-22, Spring path traversal). **WAF-FRIENDLY.** Path traversal patterns. Hits edge + direct + WAF-friendly, loses default (specific config needed). **R5: B** (R3 had A). **Down-tier vs R3.** WAF closes the window in hours and the precondition is non-default; the combination doesn't justify A.

- **CVE-2024-38816** (CWE-22, functional-router path traversal). Narrower precondition. **WAF-FRIENDLY.** **R5: B** (same as R3).

- **CVE-2020-5398** (RFD via Content-Disposition). Browser-victim chain, social-engineering tax. **WAF-MEDIUM** (filename-shape detectable but legit downloads also have weird filenames). **C.**

- **CVE-2023-20860** (auth-routing bypass via mvcRequestMatcher). **WAF-HOSTILE.** This is auth-decision bypass with a request URL that *looks legitimate* — the WAF cannot tell which endpoints are supposed to be protected; that's app-internal routing knowledge. Hits default + edge + direct + WAF-hostile. **R5: promote to S.** R3 had A. **Up-tier vs R3.** This is a four-axis hit and the WAF axis was the missing piece.

- **CVE-2023-34053** — DoS. **D.**

- **CVE-2024-22262, CVE-2024-22259** (CWE-601 open redirect). **WAF-FRIENDLY** (open-redirect patterns are signature-able though evadable). **C** (open-redirect is weak primitive regardless).

- **CVE-2024-22243** (CWE-601, SSRF in spring-web). **WAF-MEDIUM** (SSRF probes look like URL fields). **B** (R5 same as R3).

- **CVE-2022-22968** (CWE-178 case sensitivity). **WAF-MEDIUM.** **C.**

- **CVE-2022-22970, CVE-2024-22233, CVE-2018-15756** — DoS family. **D each.**

- **CVE-2018-1272, CVE-2018-1258** (CWE-863 auth bypass). **WAF-HOSTILE** — looks-legitimate request, auth misroute. **R5: A** (R3 had B). **Up-tier vs R3.** The WAF axis catches that "auth bypass with the request being indistinguishable from authorized traffic" has no perimeter control.

- **CVE-2025-41249** (CWE-285, -863, annotation auth bypass). **WAF-HOSTILE** — same logic as above; auth-decision bug, request looks legitimate. Modern, broad reach. Hits default + edge + direct + WAF-hostile. **R5: promote to S.** R3 had A. **Up-tier vs R3.**

- **CVE-2021-22118** (CWE-269 + CWE-668 in spring-web, "Improper Privilege Management"). Summary terse. CWE-269 is generic. The package and CWE pattern resemble spring-web "behavior leak" type bugs. **WAF-HOSTILE-LEANING** (whatever the bug is, it's app-internal). Without a clearer summary I treat this as **B** — direct primitive likely but precondition unclear.

---

## spring-security cluster (15 events) — individually tiered

This is the Spring/Java cluster where the WAF axis matters most. Auth-flow bugs are almost always WAF-hostile because the request that exploits them is an *authentication request* — exactly the traffic the WAF expects.

- **CVE-2022-22978** (regex-anchor auth bypass). **WAF-HOSTILE.** Path that looks protected but the regex doesn't match — the request looks like a normal HTTP GET to a normal-looking URL; the WAF has no way to know what regex protection the app *wanted*. Hits default + edge + direct + WAF-hostile. **R5: promote to S.** R3 had it "leaning S" / A. **Up-tier vs R3.** Four-axis hit, regex-confusion is common in real apps, no perimeter control.

- **CVE-2025-41232** (CWE-693, method security on private methods). **WAF-HOSTILE.** Auth check fails to fire — request looks 100% legitimate. **R5: A** (R3 had A). I considered S but loses default (specific code path with private method + reflection). Stays A.

- **CVE-2025-41248** (CWE-289, -863, annotation detection bypass). **WAF-HOSTILE.** Same shape. **R5: A** (same as R3).

- **CVE-2024-38821** (CWE-285, -770, WebFlux static-resource auth bypass). **WAF-HOSTILE.** Static-resource path that should be protected. **R5: A** (same as R3).

- **CVE-2023-34034** (CWE-281, -284, access control bypass, CRITICAL). **WAF-HOSTILE.** Direct primitive, request looks legitimate. **R5: promote to S.** R3 had A. **Up-tier vs R3.** CRITICAL severity, broad reach, four-axis hit — `**` pattern misalignment between Servlet and WebFlux dispatchers (per summary tone) means stock Spring Security configs are reachable.

- **CVE-2023-34035** (CWE-863, multi-servlet misconfig). **WAF-HOSTILE.** **R5: B** (same as R3) — operator-discovery cost is real.

- **CVE-2022-31692** (CWE-863, forward/include dispatcher type bypass, CRITICAL). **WAF-HOSTILE.** Internal forward bypasses Security filter — the *original* request reaches the WAF and looks fine; the bypass happens server-side. **R5: A** (same as R3). Could promote to S for stock-config Spring MVC apps; staying at A as the conservative call.

- **CVE-2024-22234** (CWE-284, isFullyAuthenticated misuse). API-misuse bug. **B.**

- **CVE-2024-22257** (CWE-287, -862, "erroneous authentication pass"). **WAF-HOSTILE.** Auth incorrectly passes — looks-legitimate. **R5: A** (same as R3).

- **CVE-2026-22732** (CWE-425, "Direct Request Forgery", CRITICAL). The CRITICAL severity tag is a trap. The summary "HTTP Headers Are not Written Under Some Conditions" is defense-in-depth weakening (X-Frame-Options etc.). **WAF irrelevant** — there's no payload to block; the bug is the absence of a security header from the *response*. **R5: C** (same as R3). Down-rank from CRITICAL severity.

- **CVE-2021-22112** (CWE-269 session priv-carry). **WAF-HOSTILE** (session token continues to work). **B.**

- **CVE-2021-22119** (CWE-400 + CWE-863, DoS-flavored auth). **D-leaning C** — the CWE-863 is bait; primitive is DoS. **C.**

- **CVE-2020-5407** (CWE-347, XML signature wrapping in SAML). **WAF-HOSTILE.** XML signature wrapping payloads sit inside valid SAML envelopes — the WAF doesn't deeply parse SAML by default; certainly doesn't validate signatures. Hits edge + direct + WAF-hostile. Loses default (SAML deployments are minority). **R5: A** (same as R3). For SAML deployments, treat as **S in context**.

- **CVE-2019-11272** (CWE-287, -522, creds + auth). **B** (same as R3).

- **CVE-2018-15801** (CWE-345, auth bypass). **WAF-HOSTILE.** **B** (same as R3).

---

## Spring Boot

- **CVE-2025-22235** (CWE-20, -862, EndpointRequest matcher bug → actuator exposure). **WAF-HOSTILE.** The exploited request is `/actuator/heapdump` or `/actuator/jolokia` — looks like a perfectly legitimate management URL; the WAF has no way to know the app intended these to be auth-gated. The bug is "auth matcher creates wrong matcher when actuator endpoint not exposed" — pure routing/auth confusion. Hits edge + direct + WAF-hostile, loses default (actuators are deployment-defined). **R5: A** (same as R3). The hidden gem character of this is unchanged; WAF axis confirms the elevation.

- **CVE-2023-20883** — Welcome Page DoS. **D.**

- **CVE-2022-27772** — Local LPE. **D** as remote operator.

---

## Apache Log4j (4 events)

- **CVE-2021-44228** (Log4Shell, CWE-20/-400/-502/-917). **WAF-FRIENDLY.** The signature `${jndi:` (and obfuscation variants `${${::-j}ndi:`, `${${lower:j}ndi:`, etc.) is the most-deployed emergency WAF rule in history. Cloudflare's first rule shipped within hours of Dec 9 disclosure. So why does this stay at S in R5?

  Two reasons. **(1)** The bug class is so high-volume — anywhere a user-controlled string gets logged — that WAF rules are written against the most-obvious payload-shape variants but not all. Operators ship novel encodings (Unicode-escape `${`, Punycode, header smuggling) for weeks after the initial signature ships. The window narrows but doesn't close. **(2)** This bug famously logs every input at the application layer, including inputs the WAF doesn't see at all (RMI strings, SMTP `MAIL FROM:`, internal log forwarding from non-HTTP services). The WAF axis is FRIENDLY at the perimeter but HOSTILE at the application layer for any non-HTTP ingress. Net: hits default + edge + direct, mixed-WAF (3.5 of 4). **R5: S** (same as R3). I considered down-tiering to A on pure WAF-friendliness — that's the tightest call in this report — and concluded the bug-class volume keeps it S.

- **CVE-2021-45046** (incomplete fix, patch-bypass twin). **WAF-FRIENDLY-MEDIUM.** Same payload class, smaller variant set, *post-WAF-rule-deployment.* By the time targets are between the bad patch and the good one, every WAF has the rule. The window is genuinely narrower than 44228. **R5: A.** R3 had S. **Down-tier vs R3.** The WAF axis closes this one because by the time the patch-bypass exists, the perimeter rule already shipped.

- **CVE-2021-45105** (recursion DoS). **D.**

- **CVE-2023-26464** (log4j 1.x DoS). **D.**

---

## Apache ActiveMQ (5 events)

- **CVE-2023-46604** (OpenWire deserialization RCE, CWE-502). **WAF-HOSTILE.** OpenWire is a *binary protocol on TCP port 61616*. The WAF sits in front of HTTP traffic; it does not see OpenWire AT ALL. There is no L7 perimeter control to deploy. The only mitigation is patch + firewall. Hits default (OpenWire unsafe by default) + edge (61616 reachable) + direct (gadget) + WAF-hostile. **R5: S** (same as R3). The WAF axis re-confirms this is the textbook S — *this is what WAF-hostile means*.

- **CVE-2026-34197** (Authenticated Jolokia MBean RCE). Jolokia rides over HTTP. **WAF-MEDIUM** — Jolokia request payloads (JSON with `mbean` and `operation` fields invoking known RCE-able beans like `MLet`) are signature-able but not in default rule sets. Hits edge + direct + WAF-medium, loses default (auth gate). **R5: A** (same as R3).

- **CVE-2026-39304** — DoS. **D.**

- **CVE-2019-0222** (activemq-client code injection — broker-side primitive). **C.**

- **CVE-2018-11775** (activemq-client cert validation). **C.**

---

## snakeyaml (2 events)

- **CVE-2022-1471** (Constructor Deserialization RCE). **WAF-MEDIUM-LEANING-HOSTILE.** SnakeYaml payload uses tags like `!!javax.script.ScriptEngineManager [!!java.net.URL [...]]` — those tag patterns are signature-able (medium). But:
  - Most WAFs do NOT deep-parse YAML bodies. A YAML bomb inside `Content-Type: application/x-yaml` is parsed by the application but treated as opaque by the WAF.
  - `application/x-yaml` is rare enough that emergency rules don't cover it well; default OWASP CRS doesn't include YAML body inspection.
  - YAML inside multi-part forms or smuggled in JSON-as-string is even more invisible.
  
  Hits default (unsafe constructor) + edge (when YAML-over-HTTP exists) + direct (one-shot RCE) + WAF-hostile-leaning. **R5: S** for any deployment with a YAML config endpoint (Spring Cloud Config, k8s-style configs, OpenAPI parsers); **A** otherwise. Same as R3. The WAF axis confirms the S-when-reachable call rather than changing it.

- **CVE-2022-25857** — DoS. **D.**

---

## Apache Commons (2 events)

- **CVE-2022-42889** (commons-text, CWE-94, "Text4Shell"). **WAF-FRIENDLY-MEDIUM.** The signature `${url:`, `${script:`, `${dns:` is signature-able and emergency rules shipped within a day. But the StringSubstitutor reach is application-defined — when commons-text is used internally on a string that the WAF doesn't see (config file load, log message, internal ETL), the perimeter rule doesn't help. Hits default (unsafe by default for the relevant lookups) + edge (when StringSubstitutor on user input) + direct, mixed-WAF. **R5: A** (same as R3). I considered down-tiering on WAF-friendly but the application-internal reach saves it.

- **CVE-2024-47554** (commons-io DoS). **D.**

---

## Thymeleaf (2 events, both 2026-04-15)

- **CVE-2026-40477, CVE-2026-40478** (CWE-1336, -917, Thymeleaf SSTI). **WAF-MEDIUM-LEANING-HOSTILE.** Template injection payloads like `*{T(java.lang.Runtime).getRuntime().exec(...)}` have signatures, but template syntax is varied (`#`, `*`, `~`, `@` prefixes), the payload is reflected through application-defined template names rather than a request body, and Spring Expression Language has many encoding paths. Hits primitive directness when the bug is reachable, but reach itself is per-app. **R5: A each** (same as R3). WAF axis doesn't shift these.

---

## httpclient5 (1 event)

- **CVE-2025-27820** (CWE-295, hostname-validation disabled). MITM primitive. **WAF irrelevant** — bug is at the TLS layer, before any WAF would see traffic. Needs network position. **C.**

---

## logback (2 events)

- **CVE-2023-6378** (logback serialization). **WAF-HOSTILE.** Logback's `SocketServer/ServerSocketReceiver` listens on a *raw TCP port*, not HTTP. WAF doesn't see it. Same protocol-shift pattern as ActiveMQ OpenWire and Tomcat AJP. Hits direct + edge (when receiver enabled) + WAF-hostile, loses default (receiver is opt-in and rare in prod). **R5: A** (same as R3). The campaign value is "internal pentest engagements with dev/staging logging infrastructure exposed."

- **CVE-2023-6481** — DoS. **D.**

---

## PostgreSQL JDBC (5 events)

- **CVE-2024-1597** (CWE-89, pgjdbc SQLi via line comment). **WAF-MEDIUM.** SQLi patterns are signature-rich but the bug is *driver-level* — it bypasses application-level prepared-statement defense and crafts an injection from the driver's own placeholder rewriting. WAF rules looking for `UNION SELECT` etc. still fire on the resulting query, but the application's SQLi-defense surface is broken in a way the security team didn't expect. **R5: A** (same as R3). Hidden-gem status preserved.

- **CVE-2025-49146** (CWE-287, channel-binding fallback). **WAF irrelevant** (Postgres protocol, behind WAF). **B.**

- **CVE-2022-31197** (CWE-89, refreshRow SQLi). **WAF-MEDIUM.** **B.**

- **CVE-2022-21724** (CWE-665, -668, -74, plugin class instantiation). **B.**

- **CVE-2020-13692** (CWE-611, XXE in pgjdbc). **C.**

---

## jackson-core (1 event)

- **CVE-2025-52999** (CWE-121, jackson-core stack overflow). DoS. **D.**

---

## logback (covered above)

## commons-io (covered above)

---

## Per-event tier list — full summary (R5)

### TIER S (8 unique entries — vs R3's 5)

- **CVE-2021-44228** (log4j-core) — Log4Shell. WAF-friendly but bug-class volume preserves S.
- **CVE-2023-46604** (activemq) — OpenWire unauth deser RCE. WAF-hostile (wrong protocol).
- **CVE-2021-39144** (xstream) — unauth (CWE-306) deser RCE. WAF-medium; default+edge+direct+CWE-306 too strong to drop.
- **CVE-2022-1471** (snakeyaml) — when YAML-over-HTTP reachable. WAF-hostile (YAML deep-parse rare).
- **CVE-2020-1938** (tomcat AJP) — **NEW S vs R3.** WAF-hostile (wrong protocol on port 8009).
- **CVE-2022-22978** (spring-security regex auth bypass) — **NEW S vs R3.** WAF-hostile + four-axis hit + common config pattern.
- **CVE-2023-20860** (spring auth-routing bypass) — **NEW S vs R3.** WAF-hostile + four-axis hit on stock Spring Security.
- **CVE-2023-34034** (spring-security access-control bypass, CRITICAL) — **NEW S vs R3.** WAF-hostile, broad reach.
- **CVE-2025-41249** (spring-core annotation auth bypass) — **NEW S vs R3.** WAF-hostile, modern, broad.

(That's 9. Counting CVE-2020-1938 as S-conditional-on-internal-reach gives operator a cluster to consider.)

### TIER A (heavy weaponization — ~20)

- **CVE-2022-22965** (spring-web Spring4Shell) — WAF-friendly closes window fast but bug-class breadth keeps A.
- **CVE-2025-24813** (tomcat partial PUT) — WAF-medium, non-default config.
- **CVE-2026-29145** (tomcat CLIENT_CERT) — WAF-hostile (TLS layer); S in mTLS-deployed verticals.
- **CVE-2026-34197** (activemq Jolokia) — WAF-medium, auth-gated.
- **CVE-2025-22235** (spring-boot actuator) — WAF-hostile, hidden gem.
- **CVE-2021-45046** — **down-tier from R3 S.** Patch-bypass arrives after WAF rules ship.
- **CVE-2025-41248, CVE-2025-41232** (spring-security annotation/method-security) — WAF-hostile, A.
- **CVE-2024-38821** (spring-security WebFlux static-resource bypass) — WAF-hostile, A.
- **CVE-2022-31692** (spring-security forward/include) — WAF-hostile.
- **CVE-2024-22257** (spring-security erroneous auth pass) — WAF-hostile.
- **CVE-2020-5407** (spring-security SAML signature wrapping) — WAF-hostile.
- **CVE-2023-46589, CVE-2022-42252** (tomcat smuggling) — **NEW A vs R3 (B).** WAF-hostile by definition of smuggling.
- **CVE-2018-1272, CVE-2018-1258** (spring auth-bypass) — **NEW A vs R3 (B).** WAF-hostile auth-misroute.
- **CVE-2026-40477, CVE-2026-40478** (thymeleaf SSTI) — WAF-medium-leaning-hostile.
- **CVE-2022-42889** (commons-text) — WAF-friendly closes some, internal-reach saves.
- **CVE-2023-6378** (logback socket-deser) — WAF-hostile (raw TCP).
- **CVE-2024-1597** (pgjdbc SQLi) — WAF-medium, hidden gem.
- **XStream cluster (~13 RCE entries: -10173, -26217, -29505, -39139, -39141, -39145, -39146, -39147, -39148, -39149, -39151, -39153, -39154)** — A as cluster.
- **Jackson default-typing-on subset** — A.

### TIER B (~26)

- **CVE-2025-55752** (tomcat path traversal) — WAF-friendly window closes fast.
- **CVE-2024-38819** (spring path traversal) — **down-tier from R3 A.** WAF-friendly.
- **CVE-2024-38816** (spring functional-router traversal).
- **CVE-2021-25329** (tomcat session-persist RCE) — narrow precondition.
- **CVE-2019-0232** (tomcat CGI Windows) — WAF-friendly + narrow.
- **CVE-2018-8014** (tomcat CORS) — chain primitive.
- **CVE-2024-56337, CVE-2024-50379** (tomcat TOCTOU) — **slight up-tier from R3 C.**
- **CVE-2024-22243** (spring SSRF) — WAF-medium.
- **CVE-2023-34035** (spring-security multi-servlet misconfig).
- **CVE-2024-22234** (spring-security isFullyAuthenticated).
- **CVE-2021-22112** (spring-security session priv carry).
- **CVE-2021-22118** (spring-web priv mgmt).
- **CVE-2019-11272, CVE-2018-15801** (spring-security creds/auth).
- **CVE-2025-49146** (pgjdbc channel-binding fallback).
- **CVE-2022-31197, CVE-2022-21724** (pgjdbc).
- **CVE-2020-25649, CVE-2018-14720, CVE-2018-14721, CVE-2018-19362** (jackson XXE/SSRF).
- **Jackson cluster default (B as cluster).**
- **XStream SSRF entries: CVE-2021-39150, CVE-2021-39152.**

### TIER C (~14)

- **CVE-2024-22262, CVE-2024-22259** (spring open redirect).
- **CVE-2022-22968** (case-sensitivity).
- **CVE-2020-5398** (RFD).
- **CVE-2026-22732** (spring-security headers — CWE-425 trap).
- **CVE-2021-22119** (spring-security DoS-flavored auth).
- **CVE-2021-25122** (tomcat info exposure).
- **CVE-2019-17563** (tomcat session fixation).
- **CVE-2019-12418** (tomcat creds).
- **CVE-2018-8034** (tomcat hostname).
- **CVE-2026-24734** (tomcat CWE-20 generic).
- **CVE-2025-27820** (httpclient5 hostname).
- **CVE-2018-11775** (activemq-client cert).
- **CVE-2019-0222** (activemq-client code injection — broker-side).
- **CVE-2020-13692** (pgjdbc XXE).
- **Jackson info-disclosure outliers (CVE-2019-12086, -14892, -14893).**

### TIER D (~32 unique + Jackson DoS bracket + XStream DoS bracket)

- **DoS-only events:** CVE-2026-39304, -34483, -34487, -29129; CVE-2025-53506, -52520, -52999, -48989, -48988; CVE-2024-34750, -47554, -22233; CVE-2023-46589 (DoS half), -34053, -28709, -34981, -24998, -26464, -6481, -23998 (NB CVE-2023-23998 is FileUpload — covered above as -24998); CVE-2022-45143, -42003, -42004, -25857, -22970, -22968 (case-sensitivity, marginal); CVE-2021-46877, -45105, -25122 (info, also C-bracket), -22119, -43859, -41966, -40151, -36518; CVE-2020-25657, -36518 (dup); CVE-2019-0199, -10072, -16335 (DoS subset depending on view); CVE-2018-15756, -1336.
- **Local-only:** CVE-2022-27772 (spring-boot temp-dir LPE).
- **Jackson DoS bracket** (CVE-2020-36518, CVE-2022-42003, -42004, -46877, -25657 [if present]).
- **XStream DoS bracket** (CVE-2024-47072, CVE-2022-40151, -41966, CVE-2021-43859, -21341).

---

## Summary deliverables

### 1. Tier counts (cluster-aware)

| Tier | R5 count | R3 count | Delta |
|------|----------|----------|-------|
| **S** | **8–9** | 5 | **+3 to +4** |
| **A** | **~20** | ~22 | -2 (some moved up to S, some down to B) |
| **B** | **~26** | ~26 | flat (smuggling moved up, path-traversal moved in) |
| **C** | **~14** | ~16 | -2 |
| **D** | **~32** | ~32 | flat |

R5 promotes a cluster of WAF-hostile auth-bypass / wrong-protocol bugs into S, and down-tiers WAF-friendly path-traversal / patch-bypass entries into B. The total operator portfolio at S+A is roughly the same size as R3 (~28 events) but the *composition* shifts toward bugs the WAF cannot mitigate.

### 2. Per-event tier list — full summary

(See per-cluster sections above. Copy of S-tier:)

**TIER S (R5):** CVE-2021-44228, CVE-2023-46604, CVE-2021-39144, CVE-2022-1471 (when YAML-edge), CVE-2020-1938, CVE-2022-22978, CVE-2023-20860, CVE-2023-34034, CVE-2025-41249.

### 3. Top weaponization picks (ordered, R5)

1. **CVE-2023-46604** (ActiveMQ OpenWire). Now my #1 — WAF-hostile, default-config, public TCP port. The R3 ranking had Log4Shell first; in R5 the ActiveMQ campaign has a wider window because the WAF cannot help defenders at all.
2. **CVE-2020-1938** (Tomcat AJP). Wrong-protocol, default-port, internal-network gold. R5 promotes from A; if my engagement reaches port 8009, I burn this first.
3. **CVE-2021-44228** (Log4Shell). Still S, but the WAF axis tells me to ship the campaign on day 1 and accept that day-3+ has narrower yield. Tier 1 because volume is so high that even narrow yield is huge.
4. **CVE-2022-22978** (Spring Security regex bypass). WAF-hostile auth bypass with broad-applicability config bug. New top-5 in R5.
5. **CVE-2023-20860** (Spring auth-routing bypass). WAF-hostile, stock Spring config reach.
6. **CVE-2023-34034** (Spring Security access-control bypass, CRITICAL). WAF-hostile, broad reach.
7. **CVE-2025-41249** (Spring annotation auth bypass). Modern, broad.
8. **CVE-2021-39144** (XStream unauth deser, CWE-306). Default+edge+direct+WAF-medium.
9. **CVE-2022-1471** (SnakeYaml when YAML-over-HTTP). WAF-hostile (rare-format).
10. **CVE-2022-22965** (Spring4Shell). WAF-friendly, so urgency = sprint. Lower than R3 due to WAF axis.
11. **CVE-2025-24813** (Tomcat partial PUT). WAF-medium chain.
12. **CVE-2023-46589, CVE-2022-42252** (Tomcat smuggling). WAF-hostile by definition.

R3's #1-#3 (Log4Shell, ActiveMQ, Log4Shell-bypass) becomes R5's #3, #1, "downtier" — Log4Shell still top-3 but ActiveMQ leapfrogs because the WAF axis is decisive.

### 4. Comparisons vs R3 (WAF-blind)

**Up-tiered because WAF-hostility opens the window:**

- **CVE-2020-1938 (Tomcat AJP) A → S.** AJP is wrong-protocol on port 8009; the WAF has zero visibility. Combined with default-config historical and reachable internally on most engagements, this is a textbook S in the four-axis model.
- **CVE-2022-22978 (Spring Security regex) A → S.** Auth-decision bypass with looks-legitimate URL is exactly what no WAF can defend. R3 already had this "leaning S"; R5 codifies it.
- **CVE-2023-20860 (Spring mvcRequestMatcher) A → S.** Same logic. Auth routing bypass, request looks legitimate, defender has only patch.
- **CVE-2023-34034 (Spring Security access control, CRITICAL) A → S.** Same logic. CRITICAL severity + WAF-hostile.
- **CVE-2025-41249 (Spring annotation auth) A → S.** Same logic.
- **CVE-2023-46589, CVE-2022-42252 (Tomcat smuggling) B → A.** Request smuggling is the canonical WAF-bypass primitive — by definition, the WAF and origin parse the boundary differently. R3 docked these to B for narrow proxy-mismatch precondition; R5 says the WAF axis is enough to lift them to A because the "narrow precondition" is "any cache/proxy/load-balancer in front" which is most enterprises.
- **CVE-2018-1272, CVE-2018-1258 (Spring auth-bypass) B → A.** Auth bypass with looks-legitimate request. WAF cannot help.
- **CVE-2024-56337, CVE-2024-50379 (Tomcat TOCTOU) C → B.** Marginal — the WAF-medium status of upload races plus realistic Windows-default deployments lifts these slightly.

**Down-tiered because WAF-friendliness closes the window:**

- **CVE-2021-45046 (Log4j patch-bypass) S → A.** This is the cleanest down-tier. By the time the patch-bypass exists, the perimeter rule has been deployed across the global WAF estate for days. The window for attackers is narrower than 44228's first-week sprint.
- **CVE-2024-38819 (Spring path traversal) A → B.** Path-traversal is the most WAF-blocked primitive in OWASP. Combined with non-default precondition, A is unjustified in R5.

**Held despite WAF-friendly status (sprint-window calls):**

- **CVE-2021-44228 (Log4Shell) — held at S.** Bug-class volume across non-HTTP ingress points (logging from RMI, SMTP, internal services that bypass WAF) means WAF rules at the perimeter don't catch all instances. The application-layer reach is WAF-hostile even when the perimeter primitive is WAF-friendly.
- **CVE-2022-22965 (Spring4Shell) — held at A.** Sprint window justified because WAR-deployed Spring estate is large and defender deployment of WAF rules lags the threat curve by hours-to-days.
- **CVE-2022-42889 (Text4Shell) — held at A.** Application-internal reach (commons-text used on log strings, config loads, internal ETL) means the WAF perimeter signature doesn't help even when it's deployed.

### 5. Trap picks

These are events whose CWE/severity/WAF status oversells real exploitability:

- **CVE-2026-22732 (CWE-425, "Direct Request Forgery", CRITICAL).** CRITICAL severity tag is the trap. Real primitive: response headers missing under conditions. No payload to block, no payload to weaponize. **D-leaning C.**
- **CVE-2026-29129 (CWE-327, cipher preference).** CWE-327 oversells; no exploit primitive. **D.**
- **CVE-2018-8014 (CORS supportsCredentials).** Severity HIGH and "insecure defaults" framing oversells. Three layers of "if": CORS filter enabled, credential-bearing victim, attacker-controlled origin reachable. **B at best.**
- **The Jackson DoS bracket co-tagged CWE-502.** The CWE-502 label is the trap; co-tag of CWE-400 + summary phrase "deeply nested" gives away the DoS-only nature. **D each.**
- **The XStream DoS bracket co-tagged CWE-502.** Same trap. **D each.**
- **CVE-2024-22262, CVE-2024-22259 (CWE-601 open redirect).** Open redirect *sounds* like phishing-launch; in practice modern browsers and the WAF's URL-allowlist features mostly close it. **C.**
- **CVE-2021-22119 (CWE-863 + CWE-400).** CWE-863 is bait — the bug is DoS in an auth-flow code path, not authorization bypass. **C-leaning D.**

**WAF-axis-specific traps:**

- **CVE-2024-38819 (Spring path traversal).** R3 pushed to A because direct primitive on a stock-config component. R5 says: WAF closes path-traversal in hours, the precondition is non-default; the WAF axis is the corrective. Don't get hyped by `CWE-22` directness.
- **CVE-2025-55752 (Tomcat path traversal).** Same logic. Stays B.
- **CVE-2021-45046 (Log4j patch-bypass).** WAF-blindness in R3 elevated this to S based on primitive resemblance to 44228. R5 corrects: by the time the patch-bypass exists, rules are deployed.

### 6. Hidden-gem picks (CWE/label undersells WAF-hostile primitive)

The R5 axis adds a new class of hidden gem: **the CWE/label undersells AND the bug is WAF-hostile**, meaning the operator gets long working window in addition to the misclassification protection.

- **CVE-2020-1938 (Tomcat AJP, CWE-269).** Label "Improper Privilege Management" undersells; primitive is unauth file-read on a wrong-protocol port. WAF-hostile. **The biggest hidden gem in this dataset.** Up from A (R3) to S (R5).
- **CVE-2025-22235 (Spring Boot actuator, CWE-20 + CWE-862).** Generic CWE labels. Real primitive: actuator authorization bypass with looks-legitimate `/actuator/heapdump` URL. WAF-hostile. Stays A but with stronger WAF-axis reasoning.
- **CVE-2024-1597 (pgjdbc SQLi, CWE-89).** CWE label looks generic but the *location* is the gem — driver-level SQLi bypasses application defense. WAF still fires on the SQL but the operator reaches it via paths the security team didn't expect. Stays A.
- **CVE-2022-22978 (Spring Security regex auth bypass).** R3 had the gem call right. R5 promotes to S because the WAF-hostile axis upgrades it.
- **CVE-2023-20860 (Spring mvcRequestMatcher).** Same shape as -22978. R3 had A; R5 says S.
- **CVE-2025-41249 (Spring annotation).** Same shape. R5 says S.
- **CVE-2026-29145 (Tomcat CLIENT_CERT, CWE-287).** Label correct; gem is "mTLS deployments are common in regulated industries" + WAF-hostile (TLS-layer bug). A overall, **S in mTLS-deployed verticals**.
- **CVE-2023-46589, CVE-2022-42252 (Tomcat smuggling, CWE-444).** R3 had B; R5 hidden-gem upgrade to A. Smuggling is by definition WAF-hostile — the smuggle exists because the WAF and origin disagree on parsing.
- **CVE-2023-6378 (logback socket-deser, CWE-502).** The CWE-502 label looks like the rest of the deser cluster, but this one is wrong-protocol (raw TCP) and WAF-hostile. A.
- **CVE-2018-1272, CVE-2018-1258 (Spring auth-bypass).** Looks like generic privilege-management bugs but the request that exploits them is indistinguishable from a legitimate request. WAF-hostile. R5 lifts B → A.

**The unifying R5 pattern:** when a CWE label is generic and the underlying primitive is WAF-hostile, the operator gets *both* misclassification protection (the auditor's filter may not catch it) AND a wide working window (the defender's WAF will not catch it). Those compound.

### 7. The four-axis discriminator check

**S-tier picks (R5):**

| CVE | Default-config | Network-edge | Primitive direct | WAF-hostile | Pass count |
|-----|---|---|---|---|---|
| CVE-2021-44228 | yes | yes | yes | mixed (HTTP-friendly, app-layer-hostile) | 3.5 of 4 |
| CVE-2023-46604 | yes (OpenWire unsafe) | yes (61616) | yes (gadget) | yes (wrong protocol) | 4 of 4 |
| CVE-2021-39144 | yes (no allowlist) | yes (XML POST) | yes (gadget) | medium | 3.5 of 4 |
| CVE-2022-1471 | yes (unsafe ctor) | when YAML-edge | yes | yes (rare-format) | 3.5 of 4 (conditional) |
| CVE-2020-1938 | yes (AJP-on default) | yes (port 8009 internal) | yes (file-read → JSP RCE chain) | yes (wrong protocol) | 4 of 4 |
| CVE-2022-22978 | yes (regex pattern is common) | yes | yes (full auth bypass) | yes (looks-legitimate) | 4 of 4 |
| CVE-2023-20860 | yes (mvcRequestMatcher default) | yes | yes | yes | 4 of 4 |
| CVE-2023-34034 | yes (CRITICAL, broad reach) | yes | yes | yes | 4 of 4 |
| CVE-2025-41249 | yes (annotation system default) | yes | yes | yes | 4 of 4 |

Five 4-of-4 events anchor the S-tier (46604, 1938, 22978, 20860, 34034, 41249 — actually six). The remaining three (44228, 39144, 1471) are 3.5-of-4 and are S because of complementary factors (bug-class volume, conditional-on-deployment).

**Events I tier lower despite hitting all 4 (conscious downgrade):** None in R5. The four-axis test is more honest than three-axis; the R3 "almost-S" entries (22978, 20860, 41249) get correctly promoted in R5.

**Events that hit 0/1 but I tier higher:** None at S/A. The R3 trap entries (CWE-425 oversells, CWE-327, CWE-1188 CORS) correctly stay at C/B; WAF axis doesn't rescue them.

**Edge case worth flagging:** CVE-2026-29145 (Tomcat CLIENT_CERT). Hits edge + direct + WAF-hostile, loses pure default-config because mTLS deployments are minority. R5 keeps at A globally, marks S in regulated-industry context. The four-axis model handles deployment-conditional defaults more cleanly than the three-axis did — the operator's conditional S call has principled support.

### 8. Top-of-mind operator framing

Would I run a different campaign with the R5 ranking than the R3 one?

**Yes, and meaningfully.**

Three concrete differences:

**(1) ActiveMQ leapfrogs Log4Shell as #1.** In R3, Log4Shell was the obvious top pick. In R5, the ActiveMQ campaign is more attractive because:
- Same default-config, same direct primitive.
- *The WAF cannot help defenders at all.* Log4Shell defenders have Cloudflare's `${jndi:` rule; ActiveMQ defenders have nothing because port 61616 isn't HTTP.
- The patch-deployment timeline on ActiveMQ is also slower — Java middleware has older operational practices than web tier.

So my campaign ordering swaps: ActiveMQ first, then Log4Shell as the highest-volume secondary.

**(2) Spring Security auth-bypass cluster moves to top-3 priority.** In R3, the Spring Security cluster was A-tier — strong primitives but each with per-app preconditions. In R5, the WAF axis says: these auth-bypass requests are *invisible to the WAF by design* (they look like legitimate auth attempts). Combined with the recent (2023-2025) cluster of regex/annotation/forward-include bypasses being default-config, this becomes a cluster I run *before* most deserialization bugs because:
- Lower payload size (no gadget chains).
- No payload signature.
- Defender's only mitigation is patch deploy.
- High-value primitive (full auth bypass to admin functionality).

**(3) Smuggling and AJP rise to top-priority for internal-pentest engagements.** When the engagement scope includes internal network reach:
- AJP (CVE-2020-1938) is now S — it was A in R3 because R3 didn't fully weight "wrong protocol means no WAF view."
- Smuggling (CVE-2023-46589, CVE-2022-42252) is now A — it was B in R3 because R3 treated proxy-mismatch precondition as a tax. R5 says: smuggling IS the WAF bypass; that's the entire point.

**Inverse — campaign de-emphasis:**

- I deprioritize Log4j patch-bypass (CVE-2021-45046) when the original (44228) is patched. The WAF-rule deployment tells me defenders are alert; the patch-bypass window is narrow.
- I deprioritize HTTP path-traversal (CVE-2024-38819, CVE-2025-55752) — these are the WAF's bread and butter, the window is hours-to-days at most.
- I deprioritize Spring4Shell (CVE-2022-22965) marginally — still a strong campaign but it's a sprint, not a marathon, and the WAR-only reach narrows the target estate compared to JAR-deployed Spring Boot.

**Strategic-portfolio framing:** I now run two parallel campaigns:
- **Marathon campaign** (WAF-hostile bugs): ActiveMQ, AJP, Spring Security auth bypass, Tomcat smuggling, snakeyaml-with-YAML-edge, ActiveMQ Jolokia, logback-socket. Window: weeks-to-months. Target: the long-tail patch-deployment estate.
- **Sprint campaign** (WAF-friendly bugs with strong primitives): Log4Shell first 48 hours, Spring4Shell first 24-48 hours, Text4Shell first 12-24 hours. Window: hours-to-few-days. Target: pre-rule-deployment exposure window.

The R3 single-list campaign ordering doesn't capture this distinction. R5 does.

**Final operator note on WAF axis:** The most important thing the WAF-defensibility axis adds isn't tier reordering — it's *campaign timing*. Two bugs at the same R3 tier might require completely different operational tempo. The WAF-friendly bug rewards immediate ship-and-burn-the-window; the WAF-hostile bug rewards patient cluster-targeting over months. An operator running a single rotation cadence on both wastes effort. The R5 ranking is the input to that timing decision.

---

## Closing tier-distribution table

R5 produces a final tier distribution close to R3 in volume but shifted in identity:

- **S (8-9):** 3 carry-over (Log4j-44228, ActiveMQ-46604, XStream-39144), 1 conditional carry-over (snakeyaml-1471), 5 promotions (Tomcat-1938, Spring-Sec-22978, Spring-MVC-20860, Spring-Sec-34034, Spring-41249).
- **A (~20):** Most R3 A entries hold; Log4j-45046 demotes from S; smuggling and Spring auth-bypass entries promote in from B.
- **B (~26):** path-traversal demotes in from A; smuggling promotes out; Spring auth-bypass promotes out; TOCTOU promotes in from C.
- **C (~14):** stable.
- **D (~32):** stable. WAF axis doesn't rescue DoS or local-only.

The R5 portfolio is more *operationally honest* than R3: it acknowledges that two bugs with the same primitive have different attacker economics depending on whether perimeter rules close the window. The R3 ranking already captured which bugs are weaponizable; R5 captures *how long the operator has to use them*, which is the next-most-important thing the operator wants to know.
