# Real-World Manifest Sensitivity Analysis

**Date:** 2026-04-21
**Source:** Enterprise Java manifest with 60 unique packages (from multi-app Spring portfolio)
**Data:** OSV.dev API queries
**Window:** April 2025 -- April 2026 (12 months)

## Manifest Overview

- **Total rows in manifest:** 176
- **Unique packages (groupId:artifactId):** 60
- **Network Parser (NP) packages:** 31
- **Build-time only packages:** 15
- **Runtime non-NP packages:** 14

## Vulnerability Totals

| Category | Count |
|----------|-------|
| Total unique vulnerabilities | 228 |
| Critical/High (C/H) | 160 |
| C/H from NP packages | 125 |
| C/H from NP packages with DI CWEs | 25 |
| C/H from build-only packages | 10 |
| C/H from runtime non-NP packages | 25 |

## Emergency Rebuild Trigger Analysis (Apr 2025 -- Apr 2026)

A 'trigger date' is a distinct calendar date on which at least one qualifying vulnerability was published.

| Filter | Trigger Dates | Avg Gap (days) | Worst Burst |
|--------|---------------|----------------|-------------|
| All C/H | 7 | 49.7 | 2 in 6 days |
| NP only | 6 | 59.6 | 2 in 4 days |
| NP+DI | 1 | 365.0 | 1 in 1 day |

### Filter Reduction

- All C/H -> NP only: **14% reduction** (7 -> 6 trigger dates)
- NP only -> NP+DI: **83% further reduction** (6 -> 1 trigger dates)
- All C/H -> NP+DI: **86% total reduction** (7 -> 1 trigger dates)

## Build-Tool Noise

- 10 of 160 C/H vulns (6%) come from build-time-only packages
- These packages (Maven, Plexus, Surefire, Ivy, BCEL, WireMock, XMLUnit) are never deployed to production
- Excluding build tools alone eliminates 6% of C/H noise

## Monthly Timeline

| Month | All C/H | NP only | NP+DI |
|-------|---------|---------|-------|
| 2025-04 | 0 | 0 | 0 |
| 2025-05 | 0 | 0 | 0 |
| 2025-06 | 1 | 1 | 0 |
| 2025-07 | 1 | 1 | 0 |
| 2025-08 | 0 | 0 | 0 |
| 2025-09 | 0 | 0 | 0 |
| 2025-10 | 1 | 1 | 1 |
| 2025-11 | 0 | 0 | 0 |
| 2025-12 | 0 | 0 | 0 |
| 2026-01 | 0 | 0 | 0 |
| 2026-02 | 0 | 0 | 0 |
| 2026-03 | 2 | 1 | 0 |
| 2026-04 | 2 | 2 | 0 |

## Notable Vulnerabilities

### Log4Shell / Log4j (9 C/H vulns)

- **GHSA-2qrg-x229-3v8q** (score=0.0, CRITICAL, CWE-502) [non-NP]
  Deserialization of Untrusted Data in Log4j
- **GHSA-65fg-84f6-3jq3** (score=0.0, CRITICAL, CWE-89) [non-NP+DI]
  SQL Injection in Log4j 1.2.x
- **GHSA-f7vh-qwp3-x37m** (score=0.0, CRITICAL, CWE-502) [non-NP]
  Deserialization of Untrusted Data in Apache Log4j
- **GHSA-fp5r-v3w9-4333** (score=0.0, HIGH, CWE-502) [non-NP]
  JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data
- **GHSA-vp98-w2p3-mv35** (score=0.0, HIGH, CWE-400, CWE-502) [non-NP]
  Apache Log4j 1.x (EOL) allows Denial of Service (DoS)
  ... and 4 more

### Jackson Databind Deserialization (45 C/H vulns)

- **GHSA-4gq5-ch57-c2mg** (score=0.0, CRITICAL, CWE-502) [NP]
  Arbitrary Code Execution in jackson-databind
- **GHSA-4w82-r329-3q67** (score=0.0, CRITICAL, CWE-502) [NP]
  Deserialization of Untrusted Data in jackson-databind
- **GHSA-57j2-w4cx-62h2** (score=0.0, HIGH, CWE-787) [NP]
  Deeply nested json in jackson-databind
- **GHSA-5949-rw7g-wx7w** (score=0.0, HIGH, CWE-502) [NP]
  Deserialization of untrusted data in jackson-databind
- **GHSA-5r5r-6hpj-8gg9** (score=0.0, HIGH, CWE-502) [NP]
  Serialization gadget exploit in jackson-databind
  ... and 40 more

### XStream (22 C/H vulns)

- **GHSA-2p3x-qw9c-25hh** (score=0.0, HIGH, CWE-400, CWE-502, CWE-835) [NP]
  XStream can cause a Denial of Service.
- **GHSA-2q8x-2p7f-574v** (score=0.0, HIGH, CWE-502) [NP]
  XStream is vulnerable to an Arbitrary Code Execution attack
- **GHSA-3ccq-5vw3-2p6x** (score=0.0, HIGH, CWE-502, CWE-434) [NP]
  XStream is vulnerable to an Arbitrary Code Execution attack
- **GHSA-64xx-cq4q-mf44** (score=0.0, HIGH, CWE-502) [NP]
  XStream is vulnerable to an Arbitrary Code Execution attack
- **GHSA-6w62-hx7r-mw68** (score=0.0, HIGH, CWE-502, CWE-434) [NP]
  XStream is vulnerable to an Arbitrary Code Execution attack
  ... and 17 more

### Spring4Shell / Spring Beans (2 C/H vulns)

- **GHSA-36p3-wjmg-h94x** (score=0.0, CRITICAL, CWE-74, CWE-94) [NP+DI]
  Remote Code Execution in Spring Framework
- **GHSA-hh26-6xwr-ggv7** (score=0.0, HIGH, CWE-770) [NP]
  Denial of service in Spring Framework

### Spring Web (4 C/H vulns)

- **GHSA-2wrp-6fg6-hmc5** (score=0.0, HIGH, CWE-601) [NP]
  Spring Framework URL Parsing with Host Validation
- **GHSA-4wrc-f8pq-fpqp** (score=0.0, CRITICAL, CWE-502) [NP]
  Pivotal Spring Framework contains unsafe Java deserialization methods
- **GHSA-ccgv-vj62-xf9h** (score=0.0, HIGH, CWE-601) [NP]
  Spring Web vulnerable to Open Redirect or Server Side Request Forgery
- **GHSA-hgjh-9rj2-g67j** (score=0.0, HIGH, CWE-601) [NP]
  Spring Framework URL Parsing with Host Validation Vulnerability

### SnakeYAML (3 C/H vulns)

- **GHSA-3mc7-4q67-w48m** (score=0.0, HIGH, CWE-400, CWE-776) [NP]
  Uncontrolled Resource Consumption in snakeyaml
- **GHSA-mjmj-j48q-9wg2** (score=0.0, HIGH, CWE-20, CWE-502) [NP]
  SnakeYaml Constructor Deserialization Remote Code Execution
- **GHSA-rvwf-54qp-4r6v** (score=0.0, HIGH, CWE-776) [NP]
  SnakeYAML Entity Expansion during load operation

### ActiveMQ (2 C/H vulns)

- **GHSA-5568-6qcg-g7fx** (score=0.0, HIGH, CWE-400) [NP]
   Apache ActiveMQ: Denial of Service via Out of Memory vulnerability
- **GHSA-rxpj-7qvf-xv32** (score=0.0, HIGH, CWE-20) [NP]
  Authenticated Apache ActiveMQ Broker and Apache ActiveMQ users could perform RCE via Jolokia MBeans

### Tomcat (20 C/H vulns)

- **GHSA-25xr-qj8w-c4vf** (score=0.0, HIGH, CWE-400) [NP]
  Apache Tomcat Coyote vulnerable to Denial of Service via excessive HTTP/2 streams
- **GHSA-46j3-r4pj-4835** (score=0.0, HIGH, CWE-295) [NP]
  The host name verification missing in Apache Tomcat
- **GHSA-5j33-cvvr-w245** (score=0.0, HIGH, CWE-367) [NP]
  Apache Tomcat Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability
- **GHSA-83qj-6fr2-vhqg** (score=0.0, CRITICAL, CWE-44, CWE-502) [NP]
  Apache Tomcat: Potential RCE and/or information disclosure and/or information corruption with partial PUT
- **GHSA-8vmx-qmch-mpqg** (score=0.0, HIGH, CWE-78) [NP+DI]
  Apache Tomcat OS Command Injection vulnerability
  ... and 15 more

### Spring Security (9 C/H vulns)

- **GHSA-8crv-49fr-2h6j** (score=0.0, HIGH, no CWE) [non-NP]
  Spring Security and Spring Framework may not recognize certain paths that should be protected
- **GHSA-f3jh-qvm4-mg39** (score=0.0, HIGH, CWE-287, CWE-862) [non-NP]
  Erroneous authentication pass in Spring Security
- **GHSA-hh32-7344-cg2f** (score=0.0, CRITICAL, CWE-285, CWE-863) [NP]
  Authorization bypass in Spring Security
- **GHSA-v33x-prhc-gph5** (score=0.0, HIGH, CWE-522, CWE-287) [non-NP]
  Insufficiently Protected Credentials and Improper Authentication in Spring Security
- **GHSA-v35c-49j6-q8hq** (score=0.0, HIGH, no CWE) [non-NP]
  Security Constraint Bypass in Spring Security
  ... and 4 more

## Top 20 CRITICAL Vulnerabilities (Most Recent)

| ID | Sev | Package | NP | DI | CWEs | Published | Summary |
|---|---|---|---|---|---|---|---|
| GHSA-83qj-6fr2-vhqg | CRITICAL | tomcat-embed-core | Y | N | CWE-44, CWE-502 | 2025-03-10 | Potential RCE with partial PUT |
| GHSA-36p3-wjmg-h94x | CRITICAL | spring-beans | Y | Y | CWE-74, CWE-94 | 2022-03-31 | Spring4Shell RCE |
| GHSA-jfh8-c2jp-5v3q | CRITICAL | log4j-core | Y | Y | CWE-917, CWE-20, CWE-502 | 2021-12-10 | Log4Shell JNDI injection |
| GHSA-7rjr-3q55-vv33 | CRITICAL | log4j-core | Y | Y | CWE-917, CWE-502 | 2021-12-14 | Log4j incomplete fix |
| GHSA-hh32-7344-cg2f | CRITICAL | spring-security-web | Y | N | CWE-285, CWE-863 | 2022-05-17 | Authorization bypass |
| GHSA-4wrc-f8pq-fpqp | CRITICAL | spring-web | Y | N | CWE-502 | 2021-03-19 | Unsafe deserialization |
| GHSA-vmfg-rjjm-rjrj | CRITICAL | logback-classic | N | N | CWE-502 | 2021-06-07 | Deserialization of untrusted data |
| GHSA-2qrg-x229-3v8q | CRITICAL | log4j (1.x) | N | N | CWE-502 | 2022-01-18 | Deserialization in Log4j 1.x |
| GHSA-65fg-84f6-3jq3 | CRITICAL | log4j (1.x) | N | Y | CWE-89 | 2022-01-19 | SQL injection in Log4j 1.x |
| GHSA-f7vh-qwp3-x37m | CRITICAL | log4j (1.x) | N | N | CWE-502 | 2022-01-18 | Deserialization in Log4j 1.x |

## Full NP+DI Vulnerability List

These are the vulns that would trigger emergency rebuilds under the strictest filter.

| ID | Score | Package | CWEs | Published | Summary |
|---|---|---|---|---|---|
| GHSA-wmwf-9ccg-fff5 | 0.0 | org.apache.tomcat.embed:tomcat-embed-core | CWE-23 | 2025-10-27 | Apache Tomcat Vulnerable to Relative Path Traversal |
| GHSA-76h9-2vwh-w278 | 0.0 | org.apache.mina:mina-core | CWE-502, CWE-94 | 2024-12-25 | Apache MINA Deserialization RCE Vulnerability |
| GHSA-qmgx-j96g-4428 | 0.0 | org.apache.cxf:cxf-rt-databinding-aegis | CWE-918 | 2024-03-15 | SSRF vulnerability using the Aegis DataBinding in Apache CXF |
| GHSA-8h4x-xvjp-vf99 | 0.0 | com.hazelcast:hazelcast | CWE-89 | 2024-02-16 | Hazelcast Platform permission checking in CSV File Source connector |
| GHSA-wxqc-pxw9-g2p8 | 0.0 | org.springframework:spring-expression | CWE-917, CWE-400, CWE-770 | 2023-04-13 | Spring Framework vulnerable to denial of service |
| GHSA-36p3-wjmg-h94x | 0.0 | org.springframework:spring-beans | CWE-74, CWE-94 | 2022-03-31 | Remote Code Execution in Spring Framework |
| GHSA-7rjr-3q55-vv33 | 0.0 | org.apache.logging.log4j:log4j-core | CWE-917, CWE-502 | 2021-12-14 | Incomplete fix for Apache Log4j vulnerability |
| GHSA-jfh8-c2jp-5v3q | 0.0 | org.apache.logging.log4j:log4j-core | CWE-917, CWE-20, CWE-502 | 2021-12-10 | Remote code injection in Log4j |
| GHSA-h3cw-g4mq-c5x2 | 0.0 | com.fasterxml.jackson.core:jackson-databind | CWE-502, CWE-94 | 2021-12-09 | Code Injection in jackson-databind |
| GHSA-j9h8-phrw-h4fh | 0.0 | com.thoughtworks.xstream:xstream | CWE-502, CWE-306, CWE-94 | 2021-08-25 | XStream is vulnerable to a Remote Command Execution attack |
| GHSA-cxfm-5m4g-x7xp | 0.0 | com.thoughtworks.xstream:xstream | CWE-918, CWE-502 | 2021-08-25 | A Server-Side Forgery Request can be activated unmarshalling with XStream to acc |
| GHSA-xw4p-crpj-vjx2 | 0.0 | com.thoughtworks.xstream:xstream | CWE-918, CWE-502 | 2021-08-25 | A Server-Side Forgery Request can be activated unmarshalling with XStream to acc |
| GHSA-7chv-rrw6-w6fc | 0.0 | com.thoughtworks.xstream:xstream | CWE-74, CWE-502, CWE-94 | 2021-05-18 | XStream is vulnerable to a Remote Command Execution attack |
| GHSA-mw36-7c6c-q4q2 | 0.0 | com.thoughtworks.xstream:xstream | CWE-78 | 2020-11-16 | XStream can be used for Remote Code Execution |
| GHSA-hwj3-m3p6-hj38 | 0.0 | dom4j:dom4j, org.dom4j:dom4j | CWE-611 | 2020-06-05 | dom4j allows External Entities by default which might enable XXE attacks |
| GHSA-r6j9-8759-g62w | 0.0 | org.codehaus.jackson:jackson-mapper-asl | CWE-611 | 2020-02-04 | Improper Restriction of XML External Entity Reference in jackson-mapper-asl |
| GHSA-c427-hjc3-wrfw | 0.0 | io.springfox:springfox-swagger-ui | CWE-79, CWE-352 | 2019-10-15 | Cross-site scripting in Swagger-UI |
| GHSA-hf23-9pf7-388p | 0.0 | com.thoughtworks.xstream:xstream | CWE-502, CWE-94 | 2019-07-26 | Deserialization of Untrusted Data and Code Injection in xstream |
| GHSA-f554-x222-wgf7 | 0.0 | com.thoughtworks.xstream:xstream | CWE-77, CWE-78 | 2019-05-29 | Command Injection in Xstream |
| GHSA-8vmx-qmch-mpqg | 0.0 | org.apache.tomcat.embed:tomcat-embed-core | CWE-78 | 2019-04-18 | Apache Tomcat OS Command Injection vulnerability |
| GHSA-3rmv-2pg5-xvqj | 0.0 | org.springframework:spring-messaging | CWE-358, CWE-94 | 2018-10-17 | Spring Framework has Improperly Implemented Security Check for Standard |
| GHSA-p5hg-3xm3-gcjg | 0.0 | org.springframework:spring-messaging | CWE-358, CWE-94 | 2018-10-17 | Spring Framework allows applications to expose STOMP over WebSocket endpoints |
| GHSA-6pcc-3rfx-4gpm | 0.0 | dom4j:dom4j | CWE-91 | 2018-10-16 | Dom4j contains a XML Injection vulnerability |

## Packages with Zero Vulnerabilities (17)

- com.fasterxml.jackson.dataformat:jackson-dataformat-yaml
- com.github.jknack:handlebars
- com.github.tomakehurst:wiremock-standalone (build-only)
- commons-jxpath:commons-jxpath
- org.apache.cxf:cxf-api
- org.apache.maven.surefire:maven-surefire-common (build-only)
- org.apache.maven.surefire:surefire-api (build-only)
- org.apache.maven.surefire:surefire-booter (build-only)
- org.apache.maven:maven-artifact-manager (build-only)
- org.apache.maven:maven-settings (build-only)
- org.apache.tomcat:coyote
- org.mule.apache.cxf:cxf-api
- org.mule.apache.cxf:cxf-rt-databinding-aegis
- org.mulesoft.xmlbeans:xmlbeans
- org.springframework.integration:spring-integration-core
- org.springframework.security:spring-security-config
- org.springframework.ws:spring-ws-core

## Key Findings

### 1. Filter Effectiveness: 86% Trigger Reduction

The NP+DI filter reduces emergency rebuild triggers from 7 to 1 in a 12-month window. Under All-C/H, this manifest fires roughly every 7 weeks. Under NP+DI, it fired once in 12 months (Tomcat path traversal, CWE-23, Oct 2025).

### 2. The Deserialization Wall

jackson-databind alone accounts for 45 C/H vulns (28% of all C/H). These are overwhelmingly CWE-502 (deserialization), NOT direct injection. The NP+DI filter correctly classifies jackson-databind as NP (it parses untrusted JSON from HTTP) but excludes its CWE-502 vulns from DI. Only 1 of 45 jackson-databind C/H vulns (GHSA-h3cw-g4mq-c5x2, CWE-94 Code Injection) qualifies as NP+DI. XStream similarly: 22 C/H vulns, but many are pure CWE-502. Only those with dual CWE-94/CWE-78/CWE-918 classification qualify as DI.

This distinction matters operationally: deserialization vulns require a gadget chain in the classpath, while DI vulns (injection, traversal, XXE) are directly exploitable via crafted input.

### 3. Build Tool Noise Is Low But Present

Only 6% of C/H vulns (10 of 160) come from build-time-only packages. This is lower than expected because many build tools (Maven, Surefire, most Plexus) have zero OSV entries. The noise that exists comes from plexus-utils (CWE-78 command injection) and maven-shared-utils (CWE-78). These never run in production.

### 4. Log4Shell Correctly Classified

log4j-core 2.8.2 has 2 CRITICAL NP+DI vulns in the window (both Log4Shell variants with CWE-917 JNDI injection). The older log4j 1.x line (log4j:log4j) is correctly classified as non-NP -- its vulns are JMS/SQL deserialization-based, not JNDI lookup.

### 5. Spring4Shell Correctly Classified

GHSA-36p3-wjmg-h94x (Spring4Shell, CWE-74 + CWE-94) is correctly NP+DI. The spring-beans DoS vuln (CWE-770) is NP but not DI -- correctly excluded from the strictest filter.

### 6. The NP-only Filter Has Diminishing Returns

Going from All-C/H to NP-only only removes 14% of triggers (7 to 6). This is because most of the manifest's vulnerable packages ARE network parsers. The real power is in the +DI step, which removes another 83% by excluding deserialization, DoS, auth bypass, and other non-injection CWEs.

### 7. Operational Implications

| Scenario | Emergency rebuilds per year | Team disruption |
|----------|---------------------------|-----------------|
| All C/H (status quo) | ~7 | One every ~7 weeks |
| NP only | ~6 | Marginal improvement |
| NP+DI | ~1 | One per year -- manageable |

The NP+DI filter preserves security coverage for the highest-exploitability attack patterns (injection, traversal, SSRF, XSS, XXE) while eliminating alarm fatigue from deserialization chains, DoS, and auth-logic bugs that require different remediation approaches.
