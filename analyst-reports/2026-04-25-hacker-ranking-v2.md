# Hacker Ranking — Round 2 (N=101, Cross-Ecosystem)

Operator framing: I have one quarter and a small team. I can build maybe four or five reliable exploits and weaponize a handful more if someone else publishes a working primitive first. Below is where I'd allocate that time, working from CVE summaries and CWE tags only — no KEV, no Metasploit, no breach memory.

## Ranking

### TIER S — drop everything, weaponize today

**CVE-2021-44228 — log4j-core (Maven, CWE-917)**
EL injection in a logging path that everything ships with. Anything that ever logs an attacker-influenced string is reachable: User-Agent, X-Forwarded-For, Referer, login form, anything. Pre-condition is "the app uses a vulnerable log4j and logs request data" — which is approximately all Java enterprise software. Single-shot, deterministic, blind exploitation is fine because outbound LDAP/DNS confirms.

**CVE-2021-45046 — log4j-core (Maven, CWE-917)**
Same primitive class, follow-on patch bypass. Same surface, same unauth path, same install base. Drop everything for the same reasons.

**CVE-2022-22965 — spring-webmvc (Maven, CWE-74)**
Spring MVC POJO data-binding into a property-graph that reaches the classloader on JDK9+. Default-config controller on a Tomcat-deployed Spring app, unauth, single POST, deterministic. Install base is enormous (every Spring MVC app written in the last decade). This is the textbook S-tier shape for round-1's discriminator.

### TIER A — strong candidates, would build for a campaign

**CVE-2020-17530 — struts2-core (Maven, CWE-917)**
OGNL forced double-evaluation. Struts2 is on the network edge by definition; if a tag attribute reflects an attribute name, you get full RCE. Caveat is the "vulnerable tag attribute" requirement — not every action template is shaped right. Build it, scan for it.

**CVE-2021-31805 — struts2-core (Maven, CWE-917)**
Late OGNL re-evaluation patch bypass. Same shape as 17530, similar pre-condition. A-tier because by the time it ships, the install base of remaining Struts2 deployments is enterprise legacy that does not patch — high yield, narrow population.

**CVE-2016-3081, CVE-2012-0391, CVE-2013-2251, CVE-2013-2115, CVE-2013-1965, CVE-2013-1966, CVE-2013-2134, CVE-2013-2135, CVE-2013-4316, CVE-2011-3923, CVE-2016-4461 — struts2-core (Maven, mostly CWE-94/CWE-77/CWE-74)**
The big bag of OGNL-class Struts2 RCEs. All are "send crafted parameter, get OGNL evaluation, get RCE." Each one is individually A-tier on primitive but you only need one or two that hit your target's specific Struts version. I'd weaponize the most version-flexible (3081, 0391) and treat the rest as opportunistic chain partners. Group rationale: full pre-auth RCE on a publicly reachable framework — the only thing keeping these out of S is "you have to find a Struts app that's still running and matches the version range."

**CVE-2019-0230 — struts2-core (Maven, CWE-1321)**
OGNL via attribute manipulation again. Same Struts-RCE family, same disposition. A-tier.

**CVE-2020-24616 — jackson-databind (Maven, CWE-94)**
Polymorphic deserialization gadget. Jackson is everywhere on Java REST stacks, but the bug only fires when the app calls `enableDefaultTyping()` or uses an `@JsonTypeInfo` on a field that lands on attacker-controlled JSON. Real install base of vulnerable shape is a meaningful subset, not the whole population. Build it, but it's a campaign tool not a smash-and-grab.

**CVE-2019-14379 — jackson-databind (Maven, CWE-1321)**
Another deserialization gadget. Same caveats as 24616 — needs default typing or unsafe TypeInfo. Worth building because exploitation is reliable when conditions match.

**CVE-2023-50447 — pillow (PyPI, CWE-94)**
Pillow `ImageMath.eval` — code injection via untrusted expression. Pre-condition is "the app passes user input into ImageMath," which a meaningful number of image-processing pipelines do (filters, transforms). Pillow's install base is huge in Django/Flask apps. Single-shot RCE primitive, deterministic. Pre-condition narrows it from S.

**CVE-2022-22817 — pillow (PyPI, CWE-74)**
`ImageMath.eval` arbitrary expression injection — earlier shape of the same class. Same logic, same A-tier rationale.

**CVE-2014-3007 — pillow (PyPI, CWE-78)**
Command injection in PIL's external converter shell-out. Pre-condition: app processes untrusted filenames or formats that hit the shell-out path. Old, but Pillow's surface here was wide.

**CVE-2019-5477 — nokogiri (RubyGems, CWE-78)**
OS command injection through Nokogiri's Rex/Lib gadget. Nokogiri is ubiquitous in Ruby; if the app passes user-controlled XML/XSLT through, you get a shell. A-tier because the path-to-exploit requires the app to feed user input to a specific API.

**CVE-2017-7657, CVE-2017-7656, CVE-2017-7658 — jetty-server (Maven, CWE-444)**
HTTP request smuggling / desync in Jetty. Smuggling is a lethal primitive when there's a frontend proxy parsing differently — auth bypass, cache poison, ATO. Caveat: needs a specific proxy/Jetty topology. A-tier because when it hits, it hits hard, and Jetty is broadly deployed.

**CVE-2026-29145 — tomcat-embed-core (Maven, CWE-287)**
CLIENT_CERT auth doesn't fail closed. Pre-auth bypass on any Tomcat that uses cert-auth. Install base of cert-auth Tomcats is narrow but high-value (admin consoles, internal APIs). Auth bypass primitive is deterministic — A-tier instead of S only because cert-auth isn't the default.

**CVE-2023-46589 — tomcat-embed-core (Maven, CWE-444)**
Tomcat trailer-header smuggling. Lethal primitive, but needs a fronting proxy that reassembles differently. Build it for campaigns where you've already mapped the edge.

### TIER B — opportunistic, would chain into

**CVE-2026-33937, CVE-2026-33938, CVE-2026-33940, CVE-2026-33941 — handlebars (npm, CWE-94)**
Handlebars AST type-confusion JS injection. Needs the app to compile attacker-controlled templates. That's a real but uncommon pattern (most apps compile static templates and only data is user input). 33941 is CLI-only — definitely B/C. The runtime ones are higher: SSR or template-as-config patterns expose them. Group at B; not S because "user-controlled template source" is the bottleneck.

**CVE-2019-20920, CVE-2021-23369, GHSA-2cf5-4w76-r9qv — handlebars (npm, CWE-94)**
Older handlebars RCE-via-compile-time-injection bugs. Same gating as the 2026 set: needs attacker-controlled template input. The win condition is finding apps that store templates in databases or accept them from admin uploads.

**CVE-2021-23383, CVE-2019-19919, GHSA-g9r4-xpmj-mj65 — handlebars (npm, CWE-1321)**
Prototype pollution in handlebars. PP is rarely a clean single-shot RCE; you have to find a downstream gadget in Express or Next that consumes a polluted Object.prototype. B-tier because chaining is real but requires target-specific recon.

**CVE-2020-25649 — jackson-databind (Maven, CWE-611)**
XXE in Jackson's XML module. SSRF / file-read primitive. B because XXE rarely yields RCE on modern JVMs; you chain to internal services or `/etc/passwd`-class reads.

**CVE-2018-14720, CVE-2018-14721 — jackson-databind (Maven, CWE-611, CWE-918)**
XXE and SSRF in jackson-databind. Same B disposition — chain partners, not finishers.

**CVE-2014-0225 — spring-webmvc (Maven, CWE-611)**
Spring MVC XXE. Old, narrow Spring versions. B as a chain-into for SSRF/file-read on legacy enterprise stacks.

**CVE-2025-68493 — struts2-core (Maven, CWE-611)**
Struts2 missing XML validation — XXE-class. B because the primitive is XXE not RCE; high-value if it's wired to an action that processes XML, otherwise dead air.

**CVE-2012-6685, CVE-2021-41098 — nokogiri (RubyGems, CWE-776/CWE-611)**
XXE in Nokogiri (the JRuby one is platform-restricted). Same B logic — useful chain, not a finisher.

**CVE-2025-55752 — tomcat-embed-core (Maven, CWE-23)**
Relative path traversal in Tomcat. If it reaches the WEB-INF/web.xml or arbitrary file read, that's a strong primitive on every public Tomcat. Worth building. B-tier mostly because Tomcat path-traversals usually have non-trivial pre-conditions (rewrite valve config, specific URI normalization).

**CVE-2019-0232 — tomcat-embed-core (Maven, CWE-78)**
Tomcat CGI servlet command injection on Windows-hosted Tomcat. Windows-only is the killer pre-condition. Devastating where it lands, but B because the population is narrow.

**CVE-2022-45143 — tomcat-embed-core (Maven, CWE-74)**
JsonErrorReportValve escaping issue. Looks like log/error injection — useful for log poisoning chains, not a direct RCE. B.

**CVE-2022-42252 — tomcat-embed-core (Maven, CWE-444)**
Invalid Content-Length acceptance. Smuggling primitive in front of a permissive proxy. B; same shape as the Jetty trio but I trust Tomcat's frontend topology to be more variable.

**CVE-2024-34350 — next (npm, CWE-444)**
Next.js HTTP request smuggling. Next is huge on Vercel and self-hosted SSR; smuggling against Vercel's frontend or a fronting Cloudflare/nginx is high-value. B because Vercel mitigates centrally and the self-hosted population is the realistic target.

**CVE-2025-49826 — next (npm, CWE-444)**
Next cache poisoning DoS. DoS-only is a downgrade — B at best. Could chain into a cache-deception / response-smuggling primitive depending on shape, but I'd not lead with it.

**CVE-2024-34351 — next (npm, CWE-918)**
Next Server Actions SSRF. Server Actions are now default-enabled on Next 14+, broad surface. SSRF is B unless you can chain to internal metadata endpoints (cloud creds), which on Vercel/AWS-hosted Next is plausible. Borderline A.

**CVE-2022-41721 — golang.org/x/net (Go, CWE-444)**
h2c request smuggling in golang.org/x/net. Lethal where it lands: Go HTTP frontends are common, and h2c upgrade smuggling is a beautiful primitive. B because exploitation requires h2c upgrade actually being processed (often disabled/proxied differently).

**CVE-2022-24801, CVE-2020-10108, CVE-2020-10109 — twisted (PyPI, CWE-444)**
Twisted HTTP smuggling family. Twisted's install base is moderate (legacy Python web/IRC/protocol stuff). Useful primitive, narrower target population. B.

**CVE-2024-38819 — spring-webmvc (Maven, CWE-22)**
Spring functional web frameworks path traversal. Reads sensitive files; Spring is everywhere. Weaponize if I find a Spring boot app that exposes static resource handling — B.

**CVE-2024-38816 — spring-webmvc (Maven, CWE-22)**
Same family as 38819. Same B disposition.

**CVE-2016-9878 — spring-webmvc (Maven, CWE-22)**
Older Spring ResourceServlet path traversal. B for legacy Spring deployments.

**CVE-2014-0130, CVE-2016-0752 — actionpack (RubyGems, CWE-22)**
Rails ActionPack/ActionView path traversal. Rails' install base is meaningful and these can leak source/config — B for arbitrary file read.

**CVE-2026-22860, CVE-2025-27610, CVE-2020-8161 — rack (RubyGems, CWE-22/CWE-23)**
Rack::Directory and Rack::Static path traversal. Rack::Directory is rarely used in production (it's a dev/index endpoint); Rack::Static is more common. B because they yield file-read on hosts that exposed the right middleware. Real population is small but exists.

**CVE-2024-39330 — django (PyPI, CWE-22)**
Django path traversal in storage. Specific to apps using Django's file storage with attacker-controlled names. B as a chain-into for arbitrary write/read.

**CVE-2021-31542 — django (PyPI, CWE-22)**
Django MultiPartParser uploaded-filename traversal. Needs an app that writes upload filenames to disk without normalization — common but not universal. B.

**CVE-2022-24303 — pillow (PyPI, CWE-22)**
Pillow path traversal in TempFile cleanup. Niche pre-conditions, B.

**CVE-2018-6184, CVE-2017-16877 — next (npm, CWE-22)**
Old Next.js path traversal in static handler. Default-config in those Next versions, but the affected versions are ancient — surviving install base is thin. B.

**CVE-2025-27152, CVE-2024-39338 — axios (npm, CWE-918)**
Axios SSRF via absolute URL handling. Axios is everywhere in npm. SSRF primitive targets the *application server* making the request — useful for cloud metadata exfil from a server-side axios call where the app accepts user-supplied URLs. B because it requires the app to forward user input as a URL (a real but specific pattern).

**CVE-2021-33571 — django (PyPI, CWE-918)**
Django access-control bypass that may enable SSRF/RFI/LFI. Vague summary; SSRF-class primitive is B.

### TIER C — situational / annoying

**CVE-2026-1287, CVE-2026-1207, CVE-2025-64459, CVE-2025-59681, CVE-2025-57833, CVE-2024-53908, CVE-2024-42005, CVE-2022-34265, CVE-2022-28346, CVE-2022-28347, CVE-2021-35042, CVE-2020-9402, CVE-2020-7471, CVE-2019-14234, CVE-2014-0474 — django (PyPI, CWE-89)**
The big bag of Django ORM SQLi. All of them require the app to pass user-controlled values into ORM kwargs that landed in the bypass path (column aliases, `_connector`, `Trunc/Extract`, `HasKey` on Oracle, KeyTransform on JSONField, MySQL-specific quirks, GIS extents on PostgreSQL, etc.). Django apps that follow the docs *don't* do this — the SQLi requires an app pattern of "I'll let users pick fields/orderings dynamically." That pattern exists in admin-ish dashboards and reporting tools but is the minority of Django code. Group at C: real primitive, narrow shape, hit rate per random Django app is low. I'd build one (probably 64459 `_connector` because the description says it lives in QuerySet annotation kwargs which is a more common surface) and skip the rest unless I have a specific Django target.

**CVE-2014-0472 — django (PyPI, CWE-94)**
Django code injection via `reverse()` with crafted URL name. Pre-condition is the app calls `reverse` with user input — uncommon. C.

**CVE-2013-4315, CVE-2009-2659, CVE-2011-0698 — django (PyPI, CWE-22)**
Old Django path traversals (admin media handler, ssi tag). Affected versions are now historical. C.

**CVE-2023-22794 — activerecord (RubyGems, CWE-89)**
ActiveRecord SQLi via comments. Specific feature, niche usage. C.

**CVE-2013-3221, CVE-2012-2695, CVE-2012-6496, CVE-2011-2930, CVE-2011-0448, CVE-2014-3482, CVE-2014-3483, CVE-2008-4094 — activerecord (RubyGems, CWE-89)**
The ActiveRecord SQLi backlog. Most require the app to pass user input into a `find` predicate as a Hash, range, or quoted-column position — patterns Rails best-practice has discouraged for a decade. Group at C because by the time you target a Rails app old enough to be vulnerable, you're almost certainly going through other doors first. Useful as recon-confirmation, not as lead exploit.

**CVE-2022-29216 — tensorflow (PyPI, CWE-94)**
TF `saved_model_cli` code execution. The CLI tool — not the runtime. Reachable only if a server actually invokes `saved_model_cli` on attacker-influenced model files. Niche. C.

### TIER D — pass

(No events in this round were unambiguously D. Everything above has a real primitive even if narrow. The ActiveRecord legacy SQLi cluster comes closest to D but I'm leaving it at C because there's still residual install base on old Rails apps.)

---

## Summary

### 1. Tier counts

- **S:** 3
- **A:** 21 (struts2 OGNL bag 12; tomcat 2; jetty smuggling 3; pillow 3; jackson 2; nokogiri cmd-inj 1; spring 1 — wait, recount: 11 struts items + 1 nokogiri + 3 pillow + 2 jackson + 3 jetty + 2 tomcat = 22. Counting individuals: 21–22 depending on how you slice the Struts bag.)
- **B:** ~40 (handlebars 7, jackson XXE 3, spring path 3, rack 3, actionpack 2, axios 2, twisted 3, next 4, tomcat 3, struts XXE 1, nokogiri XXE 2, golang/x/net 1, django path/SSRF 3, etc.)
- **C:** ~37 (django SQLi cluster 15, activerecord SQLi cluster 8, django old path 3, django code-inj 1, tensorflow 1, plus loose ones folded in).
- **D:** 0

Approximate: 3 / 22 / 39 / 37 / 0. Total = 101.

### 2. Top 10 weaponization picks

1. **CVE-2021-44228 (log4j)** — universal logger RCE, no pre-conditions worth mentioning.
2. **CVE-2021-45046 (log4j)** — bypass of the bypass, identical surface.
3. **CVE-2022-22965 (spring-webmvc)** — pre-auth Spring MVC RCE on JDK9+, default config.
4. **CVE-2020-17530 (struts2)** — OGNL double-eval, deterministic on vulnerable Struts.
5. **CVE-2016-3081 (struts2)** — OGNL via Content-Type, the canonical Struts edge RCE.
6. **CVE-2023-50447 (pillow)** — `ImageMath.eval` RCE in apps that pass user input to image transforms.
7. **CVE-2020-24616 (jackson-databind)** — polymorphic deserialization gadget, install base is huge.
8. **CVE-2019-5477 (nokogiri)** — Ruby OS command injection on a near-universal XML lib.
9. **CVE-2017-7657 (jetty)** — request smuggling in Jetty, lethal in CDN-fronted topologies.
10. **CVE-2026-29145 (tomcat CLIENT_CERT)** — fail-open auth bypass on any Tomcat using cert-auth (high-value internal apps).

### 3. Trap picks (CWE oversells the bug)

- **The Django CWE-89 SQLi cluster** is the biggest trap in this dataset. Sixteen entries tagged "SQL injection in Django" — and every one of them requires the app to push user input through a specific atypical ORM API (kwargs as column references, `_connector`, `Trunc/Extract`, `HasKey` on Oracle, JSONField with key transforms on certain backends, GIS aggregate extents on PostgreSQL). Django apps written normally — `Model.objects.filter(field=user_value)` — are not exposed. A defender reading "Django SQLi" would emergency-patch; an operator reading the bug shape sees a niche ORM-API misuse. The CWE label and package name combo will scare you into thinking this is universal RCE-adjacent. It is not.
- **The ActiveRecord SQLi cluster** is the same trap in Ruby. Most require a Hash-condition or quoted-column code path that Rails discouraged for a decade; modern Rails app code doesn't use them.
- **CVE-2025-49826 (next.js cache poisoning DoS)** — CWE-444 looks like smuggling, but the realistic primitive is DoS, not auth bypass. Don't confuse it with the proper smuggling bugs.
- **CVE-2025-27152 / CVE-2024-39338 (axios SSRF)** — CWE-918 plus "axios" suggests universal client-side compromise. Real shape is server-side: only matters when an axios call uses user-controlled URL input on the server. Most uses of axios on the client are unaffected; most server uses don't take user URLs.
- **CVE-2014-0472 (Django code injection via reverse)** — CWE-94 sounds like RCE in Django. Real shape requires the app to call `reverse()` on attacker-supplied URL names, which almost no real app does.
- **CVE-2022-29216 (tensorflow saved_model_cli)** — CWE-94 in TensorFlow looks scary; real shape is a CLI tool requiring server-side invocation on attacker-controlled artifacts. Niche.
- **CVE-2025-68493 (struts2 missing XML validation)** — CWE-611 is XXE not RCE; given Struts2's other RCE bugs in this list, a defender might double-prioritize this one. The other Struts bugs are the real fire.

### 4. Hidden-gem picks (CWE undersells)

- **CVE-2022-22965 (spring-webmvc, CWE-74)** — CWE-74 "generic injection" looks like a low-severity tag. Actual primitive is unauthenticated RCE on a Spring MVC controller via property graph traversal to the classloader. The CWE label oversells nothing; if anything it's understated relative to bugs labeled CWE-94. (This is more a CWE-tagging issue than a defender mis-prioritization, but worth flagging.)
- **CVE-2026-29145 (tomcat CLIENT_CERT, CWE-287)** — CWE-287 "auth bypass" sounds boring next to CWE-94/917. But fail-open cert auth on internal Tomcats lets you walk straight into admin consoles and inter-service APIs that everyone trusts. Higher-value than most RCE tags in regulated environments.
- **CVE-2017-7657 / 7656 / 7658 (jetty smuggling, CWE-444)** — request-smuggling reads as an obscure protocol nit; actual capability is stealth auth bypass and cache poisoning when there's a fronting proxy. Most defenders triage CWE-444 as "DoS-class," and that's wrong for these.
- **CVE-2019-5477 (nokogiri, CWE-78)** — OS command injection in a Ruby XML library sounds incidental. But Nokogiri is a transitive dep in essentially every Ruby web app, and the path-to-shell is short.
- **CVE-2023-50447 (pillow, CWE-94)** — CWE-94 in an image library reads like "decoder bug needs crafted file" (often a chore to weaponize). Actual shape is `ImageMath.eval` taking a user-supplied expression — that's just `eval()`. Trivially weaponizable on any pipeline that hands user input to ImageMath.

### 5. Does the round-1 discriminator hold?

Discriminator: **default-config × network-edge × primitive-directness**.

My S-tier (3): all three pass all three axes cleanly.

- log4j (44228, 45046): default config (logging is on for everything), network edge (any HTTP-handled string lands in logs), direct primitive (single-shot EL eval).
- spring4-class (22965): default config (POJO data binding is the framework default), network edge (any controller endpoint), direct primitive (single POST → classloader → RCE on JDK9+).

My A-tier mostly fails exactly one axis:

- The Struts2 OGNL bag — passes default-config and network-edge, primitive-direct, but fails *install-base-currency* (Struts2 in 2026 is mostly legacy enterprise — narrow surviving population). That's not exactly one of round-1's three axes, but it's the operator-realistic version of "default-config" in 2026.
- jackson-databind 24616 / 14379 — passes network-edge, primitive-direct, but fails default-config (needs `enableDefaultTyping` or unsafe `@JsonTypeInfo`).
- pillow ImageMath bugs — passes default-config (the API behaves this way out of the box), passes primitive-direct, fails network-edge (only reachable if the app pipes user input into ImageMath specifically).
- tomcat cert-auth 29145 — fails default-config (cert-auth isn't default).
- jetty smuggling — passes primitive-direct (smuggling is deterministic given the topology), but fails default-config in the soft sense (needs a fronting proxy that disagrees with Jetty).

So A-tier in round-2 is dominated by "passes 2 of 3 axes." That mirrors round-1's A-tier shape exactly. The interesting question is whether round-2's A-tier exploitation rate stays at round-1's 0%, or whether the bigger N flushes out the actual base rate.

D-tier is empty here (mostly because the dataset was already filtered down to NP+DI). Bugs that fail 2-or-more axes mostly landed in C — Django ORM SQLi cluster fails default-config (atypical ORM use) and primitive-directness (a SQLi primitive is rarely deterministic blind). The ActiveRecord cluster is similar.

**Events that pass all three axes but I still didn't tier S:** the handlebars compile-time RCE family (CVE-2026-33937 etc.). Default-config? Yes, AST type-confusion fires on the standard compile path. Network-edge? Only if the app accepts user-controlled templates — that's the gating pre-condition that knocks them out of "passes all three." So they actually fail network-edge on the typical-usage axis. Result: B-tier. The discriminator held.

Net read: **the discriminator holds**. S-tier in round-2 is exactly the shape of S-tier in round-1, just more of it. A-tier here will be the falsifiable test — if A-tier exploitation rate stays ≤10%, the round-1 finding generalizes and "operators only weaponize friction-free bugs" is a real pattern. If A-tier exploitation rate jumps with N, then round-1 was small-N noise.

### 6. Cross-ecosystem patterns

The discriminator looks roughly portable, with ecosystem-specific quirks:

**Java/JVM (Maven)** — the easiest operator landscape. Frameworks ship as servlets/filters that sit on the network edge by default, and JVM gadget chains turn deserialization into RCE reliably. Both my S-tier and most of A-tier are JVM. The OGNL-class Struts/Spring bugs are the platonic form of "network-edge × default-config × primitive-direct." Java's `Class.forName`/classloader plumbing is what makes data-binding into RCE tractable; you don't get this in Go or strict-typed languages.

**Python (PyPI)** — split personality. Django itself is hardened: the SQLi bag here is mostly ORM-API misuse, and that pattern lands in C. But Django apps run alongside Pillow and Twisted, and *those* libraries have legitimate eval-class primitives (ImageMath, command-line shellouts) that pop quickly. So Python's risk shape is "framework defenses plus library landmines underneath." For an operator, that means deprioritize Django-itself bugs and prioritize what Django apps tend to use (Pillow, requests, Pillow-via-Wand-via-ImageMagick patterns).

**Ruby (RubyGems)** — Rails' ORM auto-parameterization has done its job. The whole ActiveRecord SQLi cluster is C-tier because modern Rails app code doesn't hit those paths. But Nokogiri command-injection (CVE-2019-5477) is A — a single transitive dep with a shell-out in it on a near-universal Ruby web stack. Same pattern as Python: framework hardened, library underneath fragile. ActionPack path traversals are interesting middle ground — they hit the framework itself but yield only file-read.

**JavaScript/Node (npm)** — a third pattern. Prototype pollution chains and template-compile RCEs both require the app to use the library in a specific way (compile user-controlled templates, or have a pollution gadget downstream). High-impact when the conditions match, but the conditions match less often than Java's "controller endpoint exists." Next.js smuggling and SSRF are the closest to Java-class network-edge bugs in this dataset, but Vercel's centralized hosting reduces the realistic target population. So npm's S/A pipeline is narrower than Java's.

**Go (golang.org/x/net)** — only one event in the dataset. Go's typed HTTP plumbing makes deserialization-class RCE rare; smuggling is the realistic primitive. CVE-2022-41721 is real, but Go's stricter request-handling model overall caps the offensive-attack-surface ceiling lower than JVM. Single sample isn't enough to draw lines, but the prior is "Go bugs trend toward request-handling logic, not data-binding RCE."

**Cross-cutting takeaway:** the discriminator (default-config × network-edge × primitive-directness) is ecosystem-agnostic in formulation, but the *conditional probability that all three hold* differs by ecosystem. JVM web frameworks are pre-built for the all-three case (Spring/Struts data binding *is* network-edge default-config primitive-direct). Python is one library deep — Pillow yes, Django no. Ruby is the same — Nokogiri yes, ActiveRecord no. npm requires the application code to set the trap (template-as-input, pollution-gadget-present). Go's request-handling model raises the floor on how clean a primitive needs to be.

Operationally: if I have to pick one ecosystem to live in for a quarter, it's JVM web stacks. If round-2 outcomes show JVM events disproportionately exploited at the A-tier, that's confirmation. If npm and Python A-tiers exploit at parity, the discriminator is more about CWE-shape than ecosystem and round-1's pattern is robust. If only my S-tier exploits and A-tier is at zero again, the round-1 "friction-free only" finding is the real story.
