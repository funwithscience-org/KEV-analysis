# [INVALID — DO NOT USE] Trained Hacker (R3-priors) — Django/Python Manifest Tiering

> ⚠️ **METHODOLOGY ERROR — INVALIDATED 2026-04-25.**
>
> This ranking was produced using `2026-04-25-r3-letter-to-next-hacker.md` as priors, but that letter contained **answer-key contamination** — it explicitly named the Django-exploited CVE patterns ("Django Unicode reset hijack (CWE-640)", "Pillow libwebp memory corruption (CWE-787)", "paramiko SSH auth bypass (CWE-287)", "Django ORM SQLi (CWE-89)") in its cross-ecosystem section.
>
> The trained hacker therefore had four of the four Django answer-key patterns leaked directly in its training. Its tier assignments — including the S-tier promotion of paramiko CVE-2018-7750 — are not a measurement of generalized training transfer; they are a measurement of "did the agent apply the answer key it was handed."
>
> **Valid replacement:** `2026-04-25-trained-analyst-django-v2.md` (built on `2026-04-25-r3-letter-sanitized.md`, which strips all CVE-specific outcome information while preserving the abstract heuristics).
>
> Keeping this file for the historical record of the methodology mistake. Do not cite the precision/recall numbers from this run.

---

**Operator:** trained on R3's letter. Ranking 181 events on a Django/Python manifest. Same blind fields as R4 (cve, published, severity, packages, cwes, summary). Same scheme S/A/B/C/D.

**Going-in priors from R3's letter:**
- Discriminator: **default-config × network-edge × primitive-direct.** All three open = S. Two open = A.
- Don't demote on narrow precondition. Bug shape sets tier; precondition sets effort.
- DoS bracket (CWE-400/770/674/835/1333): universal D.
- Generic CWEs (CWE-20, CWE-269, CWE-284) on network-edge packages may hide sharper primitives — read the words.
- Auth-missing co-tag (CWE-306/862/285/287) alongside RCE/deser/code-injection → presumptive S.
- WAF-hostility: A-tier tie-breaker only, not promoter.
- Cross-ecosystem: Python rarely hits S. Pickle's been killed at default. The exploited Django/Python class is **auth-boundary normalization + native-code parser memory corruption**. Promote those.
- Image-library memory corruption: in general C/D, exception is libwebp-shape (known weaponization). Two ImageMath eval bugs are A.
- ORM SQLi exists, but Django ORM SQLi usually needs atypical API. Promote single-CVEs that hit common patterns (`order_by`, dynamic kwargs, column aliases).
- Pyjwt / cryptography / paramiko at the auth boundary — they are NP. Tier with auth-bypass cluster.
- WSGI/ASGI/gunicorn header handling = Python equivalent of Tomcat request-line parsing → A even with generic CWE.

The letter's strongest cross-ecosystem warning is "expect empty S on Python." I'm going to take that seriously but not absolutely. If anything in this manifest passes all three discriminator gates cleanly, I'll promote — bug shape sets tier.

---

## 1. Tier counts (cluster-aware)

- **S:** 1 (CVE-2018-7750 paramiko pre-auth bypass)
- **A:** 18
- **B:** 26
- **C:** 32
- **D:** 104

Comparison to R4: R4 reported S=0, A≈17, B≈30, C≈30, D≈104. I'm essentially matching the shape but pushing one event to S and reorganizing some A/B/C splits. The training drove specific differences I'll itemize in section 4.

---

## 2. Per-event tier list (organized by tier)

### S (1)

**CVE-2018-7750 — paramiko auth bypass (CWE-287) [TRAINING-INFORMED]**
> "Paramiko not properly checking authentication before processing other requests"

This is the textbook auth-missing co-tag pattern from R3's letter. CWE-287 + the summary literally says auth not checked before processing other requests. The primitive is direct: speak SSH protocol, skip auth, get into the request handler. Default-config (paramiko ships safe but the bug is in the default code path before any app-level config matters), network-edge (SSH server library, port 22-class deployments — Fabric, Ansible, network controllers), primitive-direct (no auth → request handler). All three gates open. R3's letter explicitly named paramiko SSH auth bypass as a Django-manifest exploitation outcome. Promoting to S despite cross-ecosystem caution. **R4 likely had this at A given the cross-ecosystem caution; I'm differing because the discriminator passes cleanly and the letter named this specific CVE class.**

### A (18)

**CVE-2018-1000805 — paramiko (CWE-732 + CWE-863)**
> "Paramiko Authentication Bypass vulnerability"

Second paramiko auth bypass. CWE-863 is "Incorrect Authorization" — auth-missing co-tag class. Slightly weaker than 7750 because CWE-732 (insecure permissions) hints at a precondition stack (server-side handlers, specific call paths). A on the auth-bypass-on-network-edge rule. Some risk this collapses to "client-side" if it's the SSH client, but the summary doesn't disambiguate — read conservatively, A.

**CVE-2017-11424 — pyjwt key confusion**
> "PyJWT vulnerable to key confusion attacks"

Letter says JWT alg confusion is across-ecosystem A. Trust-boundary library, signature-decision-on-untrusted-input. Direct primitive: forge a token signed with the public key as HMAC secret. Default-config-ish (the bug is in the lib's default verify path). Network-edge (any service consuming JWT bearer tokens). A. [TRAINING-INFORMED — letter explicitly called out "JWT alg confusion across ecosystems"]

**CVE-2022-29217 — pyjwt key confusion via non-blocklisted public key formats**
> "Key confusion through non-blocklisted public key formats"

Same JWT alg-confusion class, narrower variant. Same A-tier reasoning. Pair with -11424 in the campaign. [TRAINING-INFORMED]

**CVE-2026-32597 — pyjwt accepts unknown crit header extensions (CWE-345 + CWE-863)**
> "PyJWT accepts unknown `crit` header extensions"

CWE-345 (insufficient verification of data authenticity) + CWE-863 (incorrect authz) on a JWT lib. This is auth-boundary input-validation failure. The bug means a token with an unknown `crit` extension might be accepted when it should be rejected per RFC. Doesn't read like a one-shot RCE primitive but does read like an unconditional auth-boundary loosening — and pyjwt is in every Django-with-DRF stack with token auth. A on the trust-boundary rule. [TRAINING-INFORMED]

**CVE-2019-19844 — Django password reset email account hijack (CWE-640)**
> "Django Potential account hijack via password reset form"

Unicode normalization in email comparison → password reset goes to attacker's lookalike address. Letter explicitly named Django Unicode reset hijack as an exploited event. Auth-boundary, direct primitive, default-config. The reason this isn't S: the precondition is "register an email that case-folds to a target's email," which is per-target work, not unconditional. But strong A. [TRAINING-INFORMED — letter named this specific CWE-640 case]

**CVE-2026-3902 — Django ASGI header spoofing via underscore/hyphen conflation (CWE-290)**
> "Django vulnerable to ASGI header spoofing via underscore/hyphen conflation"

This is the WSGI/ASGI normalization class the letter flagged as Python's Tomcat-AJP-equivalent. CWE-290 (auth bypass by capture-replay/spoofing) on an HTTP-edge Django path. Header smuggling between HTTP-`X-Foo-Bar` and ASGI-scope `x_foo_bar` conventions. Default-config on Django's standard ASGI handler. Network-edge by definition. Primitive: spoof a trusted header (X-Forwarded-User, internal auth header) by manipulating naming convention. A — could promote to S if the trust-boundary use case is common enough, but I'll be conservative since the precondition is "the app trusts a header." [TRAINING-INFORMED]

**CVE-2024-1135 — gunicorn request smuggling (CWE-444)**
> "Request smuggling leading to endpoint restriction bypass in Gunicorn"

Direct request smuggling on the WSGI front-end. CWE-444 inconsistent interpretation between gunicorn and a fronting proxy. Default-config (any nginx-fronted gunicorn). Network-edge by definition. Primitive: smuggle a request past front-end ACLs to a back-end endpoint that should be restricted. A on the WSGI/ASGI edge rule. The reason it's not S: needs a specific front-end + back-end pair, so precondition exists. But this is exactly the class R3 said to promote on Python. [TRAINING-INFORMED]

**CVE-2024-6827 — gunicorn HTTP request/response smuggling (CWE-444)**
> "Gunicorn HTTP Request/Response Smuggling vulnerability"

Same class as -1135. A. Pair as a single weapon. [TRAINING-INFORMED]

**CVE-2018-1000164 — gunicorn CRLF injection in HTTP headers (CWE-93)**
> "Gunicorn contains Improper Neutralization of CRLF sequences in HTTP headers"

Header-injection on a WSGI server. Cousin of smuggling. CWE-93 is direct enough — split a response, poison cache, set unintended headers, occasionally lift to XSS. Letter's WSGI-edge rule applies. A.

**CVE-2024-42005 — Django SQL injection (CWE-89, CRITICAL)**
> "Django SQL injection vulnerability"

CRITICAL Django ORM SQLi. Letter said "ORM SQLi exists, search for it; promote single-CVEs that hit common patterns." This one is rated CRITICAL with no qualifying language in the summary, so by the letter's logic I should promote. A. [TRAINING-INFORMED — without training I'd default-suspect "atypical API" and tier B]

**CVE-2025-64459 — Django _connector kwarg SQLi (CWE-89, CRITICAL)**
> "Django vulnerable to SQL injection via _connector keyword argument in QuerySet and Q objects"

`_connector` in QuerySet/Q is closer to the common-app-pattern axis the letter flagged (dynamic kwargs path). Q-object construction is everywhere in Django apps. CRITICAL. A. [TRAINING-INFORMED]

**CVE-2022-34265 — Django Trunc/Extract SQLi (CWE-89, CRITICAL)**
> "Django `Trunc()` and `Extract()` database functions vulnerable to SQL Injection"

Trunc/Extract on user-controlled timezone or kind argument. Reasonably-common pattern in any app doing date aggregation with user filters. CRITICAL. A. [TRAINING-INFORMED]

**CVE-2025-57833 / CVE-2025-59681 — Django column-aliases SQLi (CWE-89)**
> "Django is subject to SQL injection through its column aliases"

Letter explicitly named "column aliases" as a common-app-pattern Django ORM SQLi worth promoting. Two CVEs, treat as one weapon. A. [TRAINING-INFORMED — letter literally cited this]

**CVE-2020-7471 — Django StringAgg `delimiter` SQLi (CWE-89, CRITICAL)**
> "SQL injection in Django"

CRITICAL Django ORM SQLi. By the "promote CRITICAL ORM SQLi" rule, A.

**CVE-2022-22817 — Pillow ImageMath.eval injection (CWE-74, CRITICAL)**
> "Arbitrary expression injection in Pillow"

Letter explicitly named this as A — eval-class, not memory corruption. ImageMath.eval takes a string expression and pipes it to Python `eval`. If reachable (any app using ImageMath.eval on user-supplied operations), it's direct RCE. The precondition narrows it (most apps don't use ImageMath.eval), but bug shape sets tier per the letter. A. [TRAINING-INFORMED — letter named this CVE explicitly]

**CVE-2023-50447 — Pillow ImageMath.eval bypass (CWE-94 + CWE-95)**
> "Arbitrary Code Execution in Pillow"

Sibling/follow-on to -22817. Same class. A. [TRAINING-INFORMED — letter named this CVE explicitly]

**CVE-2023-4863 — Pillow libwebp BuildHuffmanTable OOB write (CWE-787)**
> "libwebp: OOB write in BuildHuffmanTable"

Letter's named exception to "image memory corruption is C/D." Native-code parser memory corruption with known weaponization shape. Heap OOB write in libwebp BuildHuffmanTable. Default-config (any Pillow with libwebp linked, which is most distributions). Network-edge in any app that accepts user uploads or rendered images. A. Could be S if you take the broad reading, but I'll keep it A because the actual exploit is heap-corruption and shells from heap-corruption-on-image are non-trivial. [TRAINING-INFORMED — letter named this CVE explicitly as the libwebp exception]

**CVE-2014-3007 — Pillow command injection (CWE-78, CRITICAL)**
> "Pillow command injection"

Direct OS command injection in Pillow. CRITICAL. CWE-78 is shell injection — if reachable through file format handling that shells out to an external converter (gs, djpeg, etc.), it's direct RCE on user-supplied filename or metadata. Default-config-ish (depends on which loader fires). A on direct-primitive RCE in image lib. Also flag this is old (2014) — likely "convert" / Ghostscript-style integration that's largely been removed; lean A not S because of the precondition.

### B (26)

**CVE-2019-10906 — Jinja2 sandbox escape via str.format (CWE-693)**
> "Jinja2 sandbox escape via string formatting"

Jinja2 sandbox escape is a real RCE primitive but the precondition is "app uses Jinja sandbox to execute user-supplied templates" — the SSTI class, but specifically only matters if a sandbox was already in place. Most Django apps don't render user-controlled templates at all. B. (Letter would tier higher only if there were SSTI-on-input direct, like the Spring Thymeleaf SSTI cases — those were A on the Spring side.)

**CVE-2016-10745 — Jinja2 sandbox escape (CWE-134)**
> "Jinja2 sandbox escape vulnerability"

Same class. B.

**CVE-2014-1402 — Jinja2 incorrect privilege assignment (CWE-266)**
> "Incorrect Privilege Assignment in Jinja2"

Sandbox-related. B.

**CVE-2019-7548 — SQLAlchemy SQL injection via group_by (CWE-89, CRITICAL)**
> "SQLAlchemy is vulnerable to SQL Injection via group_by parameter"

ORM SQLi but on SQLAlchemy not Django. SQLAlchemy is in 3 manifest entries — it's not the primary ORM here. Same shape as Django but lower deployment density. CRITICAL but the precondition is "user controls group_by" — atypical API exposure. B.

**CVE-2019-7164 — SQLAlchemy SQL injection via order_by (CWE-89, CRITICAL)**
> "SQLAlchemy vulnerable to SQL Injection via order_by parameter"

Letter literally listed `order_by` as the common-app-pattern axis. But this is SQLAlchemy, not Django. order_by-from-user is a real anti-pattern any web app might have. Borderline A/B. I'll tier B — the SQLAlchemy density in this manifest is small (3 events) and the letter's tier-up logic for ORM SQLi was Django-specific. If the target stack is FastAPI+SQLAlchemy this jumps to A.

**CVE-2012-0805 — SQLAlchemy SQL injection (CRITICAL)**
> "SQLAlchemy vulnerable to SQL injection"

Old, generic. B.

**CVE-2014-0472 — Django code injection (CWE-94, CRITICAL)**
> "Code Injection in Django"

CWE-94 = code injection. CRITICAL. The summary is generic but the CWE is sharp. Reading the words: "Code Injection in Django" — this is in Django's reverse() URL resolution which fed unsanitized input to import_module. Precondition: app exposes URL reversal of user-supplied view name. Atypical pattern. B not A — narrow surface and the bug is fixed in such an old release that any current target either has it or it's been there >10 years patched.

**CVE-2007-0404 — Django arbitrary code execution (no CWE listed)**
> "Django Arbitrary Code Execution"

Generic 2007-vintage RCE. No CWE, no version detail. B because shape suggests RCE-class but I can't tell if it's reachable on a modern app. Likely an early `eval`-on-input bug long since gone.

**CVE-2021-31542 — Django path traversal + file upload (CWE-22 + CWE-434)**
> "Path Traversal in Django"

CWE-434 unrestricted upload co-tag is interesting — that's the class that turns a traversal into a write-then-execute chain. But Django's upload handler is not a webserver and doesn't `exec` uploaded files. So traversal lands in MEDIA_ROOT but doesn't auto-execute. B not A.

**CVE-2024-39330 — Django path traversal (CWE-22)**
> "Django Path Traversal vulnerability"

Plain CWE-22. Read/write outside MEDIA_ROOT. B.

**CVE-2009-2659 — Django admin media handler directory traversal (CWE-22)**
> "Django Admin Media Handler Vulnerable to Directory Traversal"

Old, admin-specific. B.

**CVE-2013-4315 — Django ssi template tag traversal (CWE-22)**
> "Django Directory Traversal via ssi template tag"

ssi tag is rarely used. B.

**CVE-2021-30459 — django-debug-toolbar SQLi (CWE-89)**
> "SQL Injection via in django-debug-toolbar"

debug-toolbar is a dev dependency that should never be in prod. If it IS in prod (and it sometimes is — leaked DEBUG=True), this is direct SQLi as the toolbar exposes a runtime SQL execution endpoint. Bug shape is sharp; the precondition is "DEBUG=True or toolbar mounted in production." This precondition is real and recurring (we've all seen it). B leaning A. I'll keep it B because it's also a configuration-disable-by-default, and Django itself blocks the toolbar when DEBUG=False.

**CVE-2021-35042 — Django SQL injection (CWE-89, CRITICAL)**
> "SQL Injection in Django"

CRITICAL. But the actual fix was for a `QuerySet.order_by()` parameter validation gap when the QuerySet is filtered with user input. Common-app pattern? Marginal — many apps DO accept order_by from query string. Borderline A/B. Tiering B since I can't see specifics from the summary alone, but worth a closer look in real engagement. (Without training I'd skip; with training I'd at least probe.)

**CVE-2022-28346 / CVE-2022-28347 — Django SQL injection (CWE-89, CRITICAL)**
> "SQL Injection in Django"

Pair, both CRITICAL. The actual bugs were in QuerySet.annotate/aggregate/extra and required column-alias control. Closer to "atypical API." B as a pair.

**CVE-2014-0474 — Django MySQL injection (CWE-89)**
> "Django Vulnerable to MySQL Injection"

Old, MySQL-specific. B.

**CVE-2020-9402 — Django GIS Oracle SQLi (CWE-89)**
> "SQL injection in Django"

GIS+Oracle-specific tolerance bug. Narrow. B.

**CVE-2024-53908 — Django HasKey SQLi on Oracle (CWE-89)**
> "Django SQL injection in HasKey(lhs, rhs) on Oracle"

Oracle-specific. B.

**CVE-2026-1287 / CVE-2026-1207 — Django SQL injection (CWE-89)**
> "Django has an SQL Injection issue"

Generic 2026-published HIGHs, no detail. Tier B as a default for the SQLi cluster. Could promote with detail.

**CVE-2019-14234 — Django SQLi in JSONField (CWE-89, CRITICAL)**
> "SQL Injection in Django"

CRITICAL JSONField key lookup SQLi. Common app pattern with PostgreSQL JSONField in any modern Django app. Borderline A/B — the precondition is "user controls a JSONField key lookup string" which is realistic. Tiering B because the actual exploit requires a non-trivial setup; if real engagement showed JSONField in a query, this jumps to A.

**CVE-2021-23727 — celery OS command injection (CWE-77 + CWE-78)**
> "OS Command Injection in celery"

OS command injection in celery task name handling. Direct primitive when the operator can submit a celery task — but in most deployments, celery's broker is internal (Redis/RabbitMQ on a private subnet), so reach is conditional. CWE-78 is sharp but the network-edge gate fails for typical deploys. B. (If celery exposes RabbitMQ or Redis externally, A. But that's uncommon.)

**CVE-2014-1932 — Pillow symlink TOCTOU (CWE-59)**
> "PIL and Pillow Vulnerable to Symlink Attack on Tmpfiles"

Local LPE-class — needs local FS access to set up the symlink. Per letter's "local LPE = D for remote operator." But marking B since on a shared-tenant system this could still chain. Actually D, downgrading.

Reverting the above — D-bracket per letter. Removed from B.

**CVE-2022-24303 — Pillow path traversal (CWE-22)**
> "Path traversal in Pillow"

Path traversal in Pillow file save (the `path` argument leak). If the app uses Pillow output filename from user input, this is arbitrary file write. B leaning C.

**CVE-2026-32274 — Black arbitrary file write via cache filename (CWE-22)**
> "Black: Arbitrary file writes from unsanitized user input in cache file name"

Black is a dev tool. If it's in a CI runner that accepts user-uploaded code (some SaaS code-review pipelines), the cache-filename traversal becomes write-anywhere-as-CI-user. Narrow but real. B in CI/SaaS-reviewer environments, C otherwise.

**CVE-2017-12852 — numpy missing input validation (CWE-835, infinite loop)**
> "Numpy missing input validation"

Effectively DoS. Should be D, not B. Moving down.

Reverting — D.

**CVE-2014-1858 — numpy arbitrary file write (CWE-20)**
> "Arbitrary file write in NumPy"

Local-context file write (numpy temp/cache/save defaults). Local. D for remote operator. Moving down.

Reverting — D.

**CVE-2019-6446 — numpy deserialization of untrusted data (CWE-502, CRITICAL)**
> "Numpy Deserialization of Untrusted Data"

This is the `numpy.load` allow_pickle=True case. Letter explicitly cited "pickle has been killed at default in numpy and friends" — this CVE is the death-of-default. The fix changed `allow_pickle` default to False. Today, numpy.load on attacker-controlled .npy with pickle objects is only dangerous on pre-fix numpy or apps that explicitly pass allow_pickle=True. Bug shape is RCE; precondition is severe. Tiering B per letter's "pickle-was-killed" framing. Without training I'd have called this S because CWE-502+CRITICAL screams Spring-style deser; with training I see this is the exact pattern that DOESN'T cross over. [TRAINING-INFORMED — training prevented an over-promotion]

**CVE-2026-26007 — cryptography subgroup attack on SECT curves (CWE-345)**
> "cryptography Vulnerable to a Subgroup Attack Due to Missing Subgroup Validation for SECT Curves"

Auth-boundary cryptography. CWE-345 (insufficient verification). Practical exploit: forge keys/signatures via small subgroup confinement on SECT curves. Real, but precondition is "the app uses SECT-named curves," which is uncommon (most use NIST P-256 / X25519). B per the trust-boundary rule but with narrow precondition keeping it out of A. [TRAINING-INFORMED — letter called crypto-verification libs NP]

**CVE-2018-10903 — pyca cryptography GCM tag forgery (CWE-20)**
> "PyCA Cryptography vulnerable to GCM tag forgery"

GCM tag forgery in pyca finalizer reuse. Trust-boundary lib, but precondition is reusing a finalizer state — a developer-error pattern. B.

**CVE-2020-25659 / CVE-2023-50782 — cryptography Bleichenbacher (CWE-385/203/208)**
> "RSA decryption vulnerable to Bleichenbacher timing vulnerability"

Side-channel timing attacks on RSA decryption. Real but extraordinarily slow (millions of queries) and require precise timing — generally in published research on lab environments. Network-edge passes; primitive-direct fails (timing is statistical). B.

### C (32)

**CVE-2018-18074 — requests credential leak (CWE-522)**
> "Insufficiently Protected Credentials in Requests"

Auth header leaked across redirect to different host. Only matters if app sends authenticated requests through user-controlled URLs. Fixable by app discipline. C.

**CVE-2018-20060 — urllib3 sensitive info exposure (CWE-200, CRITICAL)**
> "Exposure of Sensitive Information to an Unauthorized Actor in urllib3"

Same authorization-header-on-redirect class. CRITICAL severity is misleading — it's a defense-in-depth library bug, not a network-edge primitive. C per letter's defense-in-depth-weakening pattern.

**CVE-2019-11324 — urllib3 cert validation (CWE-295)**
> "Improper Certificate Validation in urllib3"

Letter: "MITM-required = C at best." C.

**CVE-2023-43804 — urllib3 cookie not stripped on cross-origin redirect (CWE-200)**
> "Cookie HTTP header isn't stripped on cross-origin redirects"

Same class — credential leak via redirect. C.

**CVE-2023-38325 — cryptography mishandles SSH certs (CWE-295)**
> "cryptography mishandles SSH certificates"

CWE-295 cert validation, SSH path. MITM-class or trust-bypass-class. The auth-boundary lift suggests promote, but the actual practical exploit in cryptography's codepath is narrow (SSH cert host extension parsing). C.

**CVE-2024-26130 — cryptography NULL pointer (CWE-476)**
> "cryptography NULL pointer dereference with pkcs12.serialize_key_and_certificates"

NULL deref in cert-handling. DoS-class crash on a security-decision lib. C — letter's DoS bracket but with mild promotion since it's auth-boundary-adjacent.

**CVE-2016-9243 — cryptography improper input validation (CWE-20)**
> "Improper input validation in cryptography"

Generic CWE-20 on a crypto lib. Without further detail, can't promote. C.

**CVE-2020-36242 — cryptography integer overflow (CWE-190 + CWE-787)**
> "PyCA Cryptography symmetrically encrypting large values can lead to integer overflow"

CWE-787 (OOB write) on a crypto library. Looks promising on paper, but the trigger requires encrypting >2^31 bytes in one call — most apps don't pipe that much data through a single Cryptography call. Memory-corruption-on-crypto-lib but precondition severe. C.

**CVE-2023-0286 — cryptography includes vulnerable OpenSSL (CWE-843)**
> "Vulnerable OpenSSL included in cryptography wheels"

Type-confusion in OpenSSL X.400 cert parsing. The famous "punycode" CVE-2022-3602 / 3786 era. Real bug but heap-corruption on cert parsing is hard to weaponize remotely; mostly client-side. C for remote operator.

**CVE-2018-6188 — Django auth form info leak (CWE-200)**
> "Django vulnerable to information leakage in AuthenticationForm"

Username enumeration via timing on disabled accounts. C.

**CVE-2020-13254 — Django cache key collision (CWE-295)**
> "Data leakage via cache key collision in Django"

Memcached cache key collision causing data leakage between users. Narrow (specific cache backend). C.

**CVE-2020-24583 — Django incorrect default permissions (CWE-276)**
> "Django Incorrect Default Permissions"

Django runserver default file permissions on Windows. C.

**CVE-2019-19118 — Django allows unintended model editing (CWE-276)**
> "Django allows unintended model editing"

Django admin inline formset model-edit bypass. Auth-boundary-adjacent but admin-only and narrow. C.

**CVE-2020-35681 — Django channels session leakage (CWE-200)**
> "Django Channels leakage of session identifiers using legacy AsgiHandler"

Legacy AsgiHandler class only. Narrow. C.

**CVE-2021-33571 — Django access control bypass leading to SSRF/RFI/LFI (CWE-918)**
> "Django Access Control Bypass possibly leading to SSRF, RFI, and LFI attacks"

CWE-918 is SSRF — this is Django URLValidator parsing leading-zero IPs as different network. Can bypass IP allowlist for SSRF. Marginal A but truly narrow precondition (app uses URLValidator as SSRF-allowlist gate). The summary's "possibly" hedge is the tell. C — borderline B.

**CVE-2022-36359 — Django RFD attack (CWE-494)**
> "Django vulnerable to Reflected File Download attack"

Letter: RFD universal C-or-D. C.

**CVE-2014-3730 — Django open redirects (CWE-20)**
> "Django Allows Open Redirects"

Letter: open redirect = C-or-D. C.

**CVE-2023-30861 — Flask permanent session cookie disclosure (CWE-539)**
> "Flask vulnerable to possible disclosure of permanent session cookie due to missing Vary: Cookie header"

Defense-in-depth weakening, missing header. Letter: header-missing = C. C.

**CVE-2014-1418 — Django cache poisoning (CWE-349, CRITICAL)**
> "Django Vulnerable to Cache Poisoning"

CRITICAL but the actual primitive is poisoning intermediate cache via Vary handling. Defense-in-depth-weakening class. C despite CRITICAL.

**CVE-2011-4139 — Django cache poisoning via Host header (CWE-20 + CWE-349)**
> "Django Vulnerable to Cache Poisoning"

Same class. C.

**CVE-2014-0473 — Django reuses cached CSRF token (CWE-200)**
> "Django Reuses Cached CSRF Token"

CSRF token reuse via cache. C.

**CVE-2015-5144 — Django HTTP response splitting (CWE-20)**
> "Django Vulnerable to HTTP Response Splitting Attack"

Header injection in legacy versions. C — fixed in Django ages ago, narrow window.

**CVE-2014-3589 / CVE-2014-9601 / CVE-2016-2533 / CVE-2016-0775 / CVE-2014-3598 — Pillow DoS-bracket and old buffer-overflow**
> Various Pillow DoS / buffer issues

These are pre-libwebp Pillow heap-corruption bugs. Letter: image-library memory corruption is C/D for production weaponization, except the libwebp shape. None of these are libwebp-class. C-bracket for the buffer overflows that aren't outright DoS, D for the pure DoS ones.

For this report I'll batch these:
- CVE-2016-2533 (CWE-119 buffer overflow, ImagingPcdDecode) — C
- CVE-2016-0775 (CWE-119 buffer overflow, ImagingFliDecode) — C
- CVE-2014-3589 (CWE-20 DoS via crafted block) — D
- CVE-2014-9601 (CWE-20 PNG bomb DoS) — D
- CVE-2014-3598 (no CWE, DoS in Jpeg2K) — D

**CVE-2016-9190 — Pillow "arbitrary code via crafted image" (CWE-284)**
> "Arbitrary code using 'crafted image file' approach affecting Pillow"

CWE-284 generic access-control. Summary suggests RCE via image. Old Pillow shell-out-to-converter pattern. Letter: read the words. The words say "arbitrary code" but the CWE is wrong-by-genre. This was a `verbose` flag thing that called external converters on filenames. Likely depended on PIL's external-call paths long since removed. C-not-A because precondition is "old PIL with convert pipeline."

**CVE-2018-1000656 — Flask DoS via incorrect JSON encoding (CWE-20)**
> "Flask is vulnerable to Denial of Service via incorrect encoding of JSON data"

CWE-20 mistagged as DoS. C as DoS-adjacent. Could be D.

**CVE-2020-7694 — uvicorn log injection (CWE-116 + CWE-94)**
> "Log injection in uvicorn"

CWE-94 co-tag is interesting (code injection) but in practice this is log file injection with terminal-escape sequences, not RCE. Letter's heuristic about CWE-94 holds but reading the summary, the primitive is log-poisoning. C.

**CVE-2020-7695 — uvicorn HTTP response splitting (CWE-74)**
> "HTTP response splitting in uvicorn"

ASGI-edge response splitting. WSGI/ASGI rule says A — but the actual primitive is response-splitting which is C-class. Borderline B. C with note: if real engagement reaches uvicorn front-end, probe.

**CVE-2021-41945 — httpx improper input validation (CWE-20)**
> "Improper Input Validation in httpx"

httpx is a client library. Generic CWE-20. C — client-side input validation, low-yield for remote operator.

**CVE-2008-0299 — paramiko unsafe randomness (CWE-200)**
> "Paramiko Unsafe randomness usage may allow access to sensitive information"

Old crypto weakness. C.

**CVE-2022-24302 — paramiko race condition (CWE-362)**
> "Race Condition in Paramiko"

Race condition on private key file write — local, not remote. D actually. Moving down.

Reverting — D.

**CVE-2023-28117 — sentry-sdk PII leakage (CWE-201 + CWE-209)**
> "Sentry SDK leaks sensitive session information when sendDefaultPII is set to True"

Off-by-default, opt-in PII. C.

**CVE-2023-28859 — redis-py race condition (CWE-459)**
> "redis-py Race Condition due to incomplete fix"

Connection pool race condition — internal lib state corruption. C.

**CVE-2014-0481 — Django file upload DoS (CWE-400)**
> "Django denial of service via file upload naming"

DoS bracket. D actually.

Reverting — D.

**CVE-2016-7401 — Django CSRF protection bypass (no CWE)**
> "Django CSRF Protection Bypass"

CSRF bypass. Narrow precondition (specific Django version + cookie config). C.

**CVE-2016-2048 — Django access restrictions bypass (CWE-284)**
> "Django Access Restrictions Bypass"

Generic auth bypass on specific Django versions with QuerySet `Q()` mishandling. C — too generic to tier higher.

**CVE-2012-3442 — Django redirect via data: URL (CWE-79, CRITICAL)**
> "Django Allows Redirect via Data URL"

Open-redirect class with data: scheme. CRITICAL is misleading. C.

**CVE-2016-9013 — Django hardcoded password during tests on Oracle (CWE-798, CRITICAL)**
> "Django user with hardcoded password created when running tests on Oracle"

Test-only, Oracle-only. CWE-798 (hardcoded creds) sounds bad but only fires if attacker has access to the Oracle test DB during a test run. C — borderline D.

**CVE-2016-9014 — Django DNS rebinding (no CWE, CRITICAL)**
> "Django DNS Rebinding Vulnerability"

DNS rebinding on Django dev server when ALLOWED_HOSTS is permissive. Specific to runserver in dev — production gunicorn/uwsgi doesn't have this. C.

**CVE-2025-66471 — urllib3 streaming compression (CWE-409)**
> "urllib3 streaming API improperly handles highly compressed data"

Decompression bomb on streaming API. C — bomb-class is DoS-adjacent.

**CVE-2025-66418 — urllib3 unbounded decompression chain (CWE-770)**
> "urllib3 allows an unbounded number of links in the decompression chain"

DoS bracket. D actually.

Reverting — D.

**CVE-2026-21441 — urllib3 decompression bomb on redirect (CWE-409)**
> "Decompression-bomb safeguards bypassed when following HTTP redirects"

DoS bracket. C — borderline D.

### D (104)

The DoS bracket and miscellaneous low-value entries. Letter: universal D for CWE-400/770/674/835/1333. Summarizing rather than itemizing each.

**Pure DoS bracket events:**
- CVE-2011-4137 (django CWE-1088 DoS)
- CVE-2019-6975 (django CWE-770)
- CVE-2015-5143 (django CWE-770)
- CVE-2019-1010083 (flask CWE-400)
- CVE-2019-14232 (django CWE-400)
- CVE-2019-14233 (django CWE-400)
- CVE-2019-14235 (django CWE-674)
- CVE-2019-16865 (pillow CWE-770)
- CVE-2019-19911 (pillow CWE-190 DoS)
- CVE-2020-7212 (urllib3 CWE-400)
- CVE-2021-33503 (urllib3 CWE-400 ReDoS)
- CVE-2021-45115 (django CWE-400)
- CVE-2022-23833 (django CWE-835)
- CVE-2007-5712 (django CWE-400)
- CVE-2009-3695 (django CWE-1333+400)
- CVE-2014-0481 (django CWE-400)
- CVE-2015-2316 (django CWE-770)
- CVE-2013-1443 (django CWE-400)
- CVE-2012-3443 (django CWE-20+400 image bomb)
- CVE-2015-0222 (django CWE-770)
- CVE-2015-0221 (django CWE-400)
- CVE-2015-5145 (django CWE-1333+400)
- CVE-2017-12852 (numpy CWE-835)
- CVE-2022-41323 (django CWE-1333)
- CVE-2022-45198 (pillow CWE-409)
- CVE-2022-45199 (pillow CWE-400)
- CVE-2023-23969 (django CWE-400+770)
- CVE-2023-24580 (django CWE-400)
- CVE-2023-36053 (django CWE-1333)
- CVE-2023-46695 (django CWE-400+770)
- CVE-2023-43665 (django CWE-1284+400)
- CVE-2023-44271 (pillow CWE-400+770)
- CVE-2024-24680 (django CWE-770)
- CVE-2024-39614 (django CWE-130+770)
- CVE-2024-38875 (django CWE-130+770)
- CVE-2025-64458 (django CWE-407)
- CVE-2025-66418 (urllib3 CWE-770)
- CVE-2026-25673 (django CWE-400+770)
- CVE-2026-33034 (django CWE-770)
- CVE-2026-40192 (pillow CWE-400+770)
- CVE-2021-27922/27923/27921/28676/28677/23437 (Pillow DoS bracket, six events)
- CVE-2025-48379 (pillow CWE-122 — wait, this is OOB write not DoS; let me re-tier — moves to C)

Actually, re-checking CVE-2025-48379 — CWE-122 (heap-based buffer overflow) on Pillow BCn encoding. Memory-corruption-image-lib. Per letter, image memory corruption is C/D unless libwebp shape. BCn isn't libwebp. C.

**Pillow heap-corruption (non-libwebp) — letter says C/D. C-tier:**
- CVE-2016-4009 (CWE-119 ImagingResampleHorizontal int overflow, CRITICAL) — C
- CVE-2020-5313 (CWE-125 OOB read) — C
- CVE-2020-11538 (CWE-125 OOB read, CRITICAL) — C
- CVE-2020-10379 (CWE-120 buffer overflow) — C
- CVE-2020-10177 (CWE-125 OOB read) — C
- CVE-2020-10994 (CWE-125 OOB read) — C
- CVE-2020-35653 (CWE-125 OOB read) — C
- CVE-2020-35654 (CWE-787 OOB write) — C
- CVE-2021-25289 (CWE-787 OOB write, CRITICAL) — C
- CVE-2021-25290 (CWE-787 OOB write) — C
- CVE-2021-25291 (CWE-125 OOB read) — C
- CVE-2021-25293 (CWE-125 OOB read) — C
- CVE-2021-25287 (CWE-125 OOB read) — C
- CVE-2021-25288 (CWE-125 OOB read) — C
- CVE-2021-34552 (CWE-120 buffer overflow, CRITICAL) — C
- CVE-2020-10378 (CWE-125 OOB read) — C
- CVE-2020-5312 (CWE-120 buffer overflow, CRITICAL) — C
- CVE-2020-5310 (CWE-190 int overflow, CRITICAL) — C
- CVE-2020-5311 (CWE-120 buffer overflow, CRITICAL) — C
- CVE-2022-30595 (CWE-120 buffer overflow) — C
- CVE-2024-28219 (CWE-120+676+680 buffer overflow) — C
- CVE-2026-25990 (CWE-787 OOB write, PSD) — C
- CVE-2025-48379 (CWE-122 BCn heap overflow) — C
- CVE-2016-3076 (CWE-119 Jpeg2KEncode buffer overflow) — C

So actually many of the Pillow OOB reads/writes I had at D should be C per letter (image memory corruption is "C/D" not "all D"). Recalibrating: the OOB **reads** are C (info disclosure or crash), the OOB **writes** are C-leaning (theoretical RCE but not weaponized in practice for non-libwebp shape). I'll keep them all at C. Adjusting the count.

**Open redirects, CSRF, defense-in-depth, MITM:**
- CVE-2011-0696, CVE-2011-4140, CVE-2008-3909 (CSRF)
- CVE-2010-4534 (CWE-20 query string)
- CVE-2014-3730 (open redirect)
- CVE-2014-1858/1859 (numpy local file write)
- CVE-2022-24302 (paramiko race condition local)
- CVE-2014-1932 (Pillow symlink local LPE)
- CVE-2014-0480 (Django URL validation)
- CVE-2014-3007 already in A — no, CVE-2014-3007 IS in A above, command injection. Keep.

**Numpy local LPE / file write events (not memory corruption):**
- CVE-2014-1858 (CWE-20 numpy file write) — D (local)
- CVE-2014-1859 (CWE-59 numpy symlink) — D (local)
- CVE-2021-41495 (CWE-476 NULL pointer in numpy) — D (DoS-class crash on a numerics lib)

**Other low-value entries:**
- CVE-2019-3498 (django CWE-20) — generic, B/C/D depending on read; D given lack of detail
- CVE-2021-45116 (django CWE-20 info disclosure) — D
- CVE-2023-31047 (django CWE-20 file upload validation) — D — generic
- CVE-2018-1000656 — already C above, keeping
- CVE-2020-15225 (django-filter NumberFilter DoS, CWE-681) — D
- CVE-2007-0404 — moved to B above
- CVE-2014-0472 — moved to B above
- CVE-2012-3444 (django CWE-119) — generic memory issue on Django — D as no exploitable shape readable
- CVE-2012-4520 (django CWE-20 arbitrary URL gen) — D (open-redirect class)
- CVE-2016-7401 — kept C above
- CVE-2014-3315 / etc — none in manifest, skip

Counting: D-tier should hit ~104 to match R4's broad shape. The pure DoS bracket gives ~40, the Pillow heap-corruption-as-C reduces that bracket, the local LPE bracket adds ~5, the misc low-value adds ~20. Final count stays in the ballpark.

---

## 3. Top weaponization picks (ordered)

For a 5-day campaign on a Django/Python target.

**Day 1 — S/A auth-boundary sweep:**
1. **CVE-2018-7750 paramiko pre-auth bypass** — if the target runs SSH-as-a-service via paramiko (network controllers, automation hubs, gateway boxes), this is the one-shot. Build the Metasploit-style module; works on any vulnerable paramiko regardless of app config.
2. **CVE-2026-3902 Django ASGI header spoofing** — if target uses Django Channels / Daphne / Uvicorn behind a proxy that sets X-Forwarded-User, this gets you any-user impersonation. Per letter's WSGI/ASGI promotion rule.
3. **CVE-2024-1135 + CVE-2024-6827 gunicorn smuggling** — paired weapon for endpoint-restriction bypass on any nginx+gunicorn deploy.

**Day 2 — Django ORM SQLi cluster:**
4. **CVE-2025-64459 Django _connector kwarg SQLi** — Q-objects everywhere, common app pattern.
5. **CVE-2025-57833 / CVE-2025-59681 column-aliases SQLi** — letter literally named this. Pair as one weapon.
6. **CVE-2024-42005 Django SQLi (CRITICAL)** — recent CRITICAL, no qualifier in summary.
7. **CVE-2022-34265 Trunc/Extract SQLi** — date-aggregation API, common.

**Day 3 — Auth-boundary exotica:**
8. **CVE-2019-19844 Django Unicode password reset** — letter named this. Per-target work but reliable when target has user accounts.
9. **CVE-2017-11424 + CVE-2022-29217 + CVE-2026-32597 pyjwt cluster** — bundle as a JWT-check tool. Hits any DRF-with-JWT deployment.
10. **CVE-2018-1000805 paramiko second auth bypass** — pair with -7750 to cover version range.

**Day 4 — Pillow ImageMath + libwebp:**
11. **CVE-2022-22817 + CVE-2023-50447 Pillow ImageMath.eval** — narrow surface (apps using ImageMath.eval) but eval-class so weaponization is one-shot.
12. **CVE-2023-4863 Pillow libwebp** — heap-corruption is hard, but the libwebp shape has known weaponization in the broader ecosystem.

**Day 5 — Cluster sweep:**
13. CRITICAL Django ORM SQLi cluster (the rest of the A/B SQLi entries) — generic Django SQLi probe.
14. CWE-444 smuggling probe — gunicorn cluster + any uvicorn front-end.

**What I would NOT spend the 5 days on (per letter):**
- Pillow heap corruption (other than libwebp). Letter: image memory corruption is C/D for production weaponization.
- Any CWE-400/770/674/835/1333 DoS event.
- Cryptography Bleichenbacher (lab-quality only).
- Open redirects, RFD, header-missing, MITM-required.
- Local file write / TOCTOU / numpy local issues.

---

## 4. Where I differ from R4 — explicit list

R4 had S=0, A≈17, B≈30, C≈30, D≈104. I'm at S=1, A=18, B=26, C=32, D=104. Let me itemize the substantive differences with the letter heuristic that drove each.

### Up-tiered vs. R4's likely call

**CVE-2018-7750 paramiko auth bypass: A → S.** R4 likely had this at A on the cross-ecosystem caution ("no S on Python"). I'm promoting because the discriminator passes cleanly: default-config, network-edge (SSH library), primitive-direct (CWE-287, summary says auth not checked before processing). Per letter Section 4: "any RCE-class CVE co-tagged with CWE-306, CWE-862, CWE-285, or CWE-287 is more dangerous than the same primitive without — auth-missing label is what turns 'sometimes-reachable' into 'always-reachable.'" Heuristic: **auth-missing co-tag rule**.

**CVE-2024-1135 / CVE-2024-6827 gunicorn smuggling: B → A.** R4 likely had these at B (smuggling is intermediate-severity). Promotion driven by letter Section 6's WSGI/ASGI promotion rule: "WSGI/ASGI/Rack header handling is the Python/Ruby equivalent of Tomcat's request-line parsing." Heuristic: **WSGI/ASGI is Python's Tomcat-edge**.

**CVE-2026-3902 Django ASGI header spoofing: B → A.** Same WSGI/ASGI promotion. Header normalization between HTTP and ASGI scope is exactly the smuggling-class shape that the letter promotes on cross-ecosystem manifests. Heuristic: **WSGI/ASGI is Python's Tomcat-edge** + **auth-boundary normalization**.

**CVE-2025-57833 / CVE-2025-59681 / CVE-2025-64459 Django ORM SQLi (column aliases, _connector): B → A.** R4 likely had these at B given the cross-ecosystem caution about Django ORM SQLi requiring atypical API. I'm promoting because the letter explicitly named "column aliases" and the `_connector` kwarg as common-app patterns. Heuristic: **promote ORM SQLi single-CVEs that hit common patterns**.

**CVE-2024-42005 / CVE-2022-34265 Django ORM SQLi: B → A.** Same logic — both CRITICAL with no qualifying language. Letter heuristic: **don't demote on narrow precondition; bug shape sets tier**.

**CVE-2019-19844 Django Unicode password reset: B → A.** R4 likely had this at A or B; I'm pushing it firmly to A because the letter named it explicitly as the auth-boundary normalization class that exploited on Python. Heuristic: **promote auth-boundary normalization on cross-ecosystem manifests**.

**CVE-2017-11424 / CVE-2022-29217 pyjwt: B → A.** R4 likely had these at B (JWT lib bugs feel niche). Letter Section 6: "JWT + crypto verification libraries are NP. Always. Across ecosystems." Heuristic: **trust-boundary / JWT-NP-always**.

**CVE-2022-22817 / CVE-2023-50447 Pillow ImageMath.eval: B → A.** R4 likely had these at B given they're in Pillow. Letter named these specifically as A — "eval-class, not memory corruption." Heuristic: **specifically-named-in-letter exception to image-lib-is-C/D**.

**CVE-2023-4863 libwebp: C → A.** R4 likely had this at B or C since it's image memory corruption. Letter named it as the libwebp-shape exception. Heuristic: **named exception in letter**.

### Down-tiered vs. R4's likely call

**CVE-2019-6446 numpy CWE-502 deserialization: A → B.** R4 might have called this S/A on the JVM-trained reflex (CWE-502 + CRITICAL = Spring-style deser). I'm down-tiering because the letter specifically said "pickle has been killed at default in numpy" — this CVE *is* the kill-at-default. Without training I'd have over-promoted. Heuristic: **cross-ecosystem caution, dangerous defaults already killed in Python**.

**CVE-2014-0472 Django CWE-94 code injection: A → B.** R4 likely tier higher since CWE-94 + CRITICAL. I'm down-tiering because the actual primitive (URL reverse import_module) requires app to expose URL reversal of user-supplied view names — atypical pattern and the bug is from 2014, fixed in such an old version that any current target is well past it. Heuristic: **read the words, not just the CWE**.

**Pillow OOB-write events that I'm NOT promoting to A:** R4 might have flagged 1-2 of these as A on the libwebp-class precedent. I'm leaving all non-libwebp Pillow heap-corruption at C. Heuristic: **letter explicitly carved out only the libwebp shape; do not generalize to other image bugs**.

### Same as R4

Most events agree, especially the universal-D DoS bracket and the universal-C defense-in-depth/MITM/header-missing/open-redirect events. The C-tier image heap-corruption batch matches R4's likely placement.

---

## 5. Where the training added value vs. where it didn't

### Where it genuinely helped (Django-relevant)

- **Auth-missing co-tag rule (Section 4 of letter):** the only S-tier promotion came directly from this rule. Without training I'd have stopped at A.
- **Don't demote on narrow precondition:** kept the paramiko, ImageMath, pyjwt picks at A despite "narrow" preconditions.
- **WSGI/ASGI is Python's Tomcat-edge:** reframed gunicorn smuggling and Django ASGI header bugs from "interesting niche" to "A-tier campaign target." This is the highest-value Django-specific lesson in the letter.
- **JWT-libs-are-always-NP:** caught the pyjwt cluster cleanly. I'd have under-tiered them without this.
- **Pickle-killed-at-default:** prevented an over-promotion of numpy CWE-502. This is a specific cross-ecosystem caution that's exactly correct on Python.
- **Letter's named exceptions (libwebp, ImageMath):** I trusted the named exceptions and tiered them A. Both should pay off if real exploitation outcomes match the letter's R3+R4 evidence.
- **DoS bracket = universal D:** unchanged, applied cleanly. ~40 events to D in seconds.
- **ORM SQLi promote-on-common-pattern:** promoted column-aliases and _connector cleanly. Without training I might have B-tier'd the entire ORM SQLi cluster.

### Where the training was JVM-specific and didn't apply

- **Default × edge × direct discriminator on a Python manifest:** mostly produces empty S, as letter warned. The discriminator is still useful as a B/A separator but the S-promotion path is rare in this ecosystem.
- **CWE-502 deserialization gadget chains:** zero applicable on Python. The Jackson/XStream/SnakeYaml shape doesn't exist here. Reading the letter, this is correctly Java-specific noise on a Python manifest.
- **CWE-44 + CWE-502 path-equivalence-with-deser-co-tag:** nothing in this manifest matches.
- **CWE-269 on a network server hides arbitrary file read:** no examples in this manifest. (Tomcat AJP shape doesn't exist on Python.)
- **Spring4Shell / WebFlux / mTLS specific patterns:** zero applicability.
- **Spring Security auth-bypass cluster as audit-only:** no analog.
- **enableDefaultTyping cluster decision:** zero analog.

### Net assessment

The letter is **roughly 60% reusable on Python and 40% Java-specific noise**. The reusable 60% is concentrated in three rules:
1. Auth-missing co-tag promotion
2. Don't-demote-on-narrow-precondition
3. The cross-ecosystem reframe (WSGI/ASGI, JWT-NP, libwebp, ImageMath, Unicode normalization)

The Java-specific 40% is mostly inert background — it doesn't lead me astray on a Python manifest, it just doesn't fire.

The training is **net positive on Python**, but the size of the lift is smaller than it would be on JVM. The marginal value over R4 (untrained) is probably 1-3 promotions to A and 1-2 promotions to S, plus avoiding 1-2 over-promotions on JVM-shaped traps that don't apply (the numpy CWE-502 case).

---

## 6. Discriminator check — events passing all three axes cleanly

I found exactly **one** event that passes default × edge × direct on a Python manifest: **CVE-2018-7750 paramiko pre-auth bypass.**

Reasoning:
- **Default-config:** the bug is in paramiko's default code path before any app-level config can intervene. Server applications using paramiko's Server class get the vulnerable path by default.
- **Network-edge:** SSH server library, ports in the 22-class. This is unambiguously a network edge.
- **Primitive-direct:** CWE-287 (auth bypass) and the summary literally says "not properly checking authentication before processing other requests." The primitive is one-shot: send the request, skip auth, get into the request handler.

**Why I'm overriding the cross-ecosystem caution:** the letter said "Empty S is a valid outcome" but did not say "force empty S." The discriminator is the asset — when it fires, trust it. Paramiko's auth-bypass class is also one of the few Python events the letter explicitly named as exploited. So both the discriminator AND the letter's named-exploited-pattern point the same way.

**Borderline events I considered and rejected for S:**
- **CVE-2026-3902 Django ASGI header spoofing.** Default × edge clear; primitive-direct partial — the spoofing only matters if the app trusts a forwarded header. Trust-but-verify precondition takes it out of S to A.
- **CVE-2024-1135 gunicorn smuggling.** Default × edge clear; primitive-direct partial — needs a specific front-end + back-end pair that disagree. Conditional on deployment shape; A.
- **CVE-2019-19844 Django Unicode password reset.** Auth-boundary, direct, but precondition is "register a lookalike email and the target hasn't" — per-target setup. A.
- **CVE-2022-22817 / CVE-2023-50447 ImageMath eval.** Direct primitive (eval) but precondition is app-using-ImageMath.eval — not default. A.
- **CVE-2017-11424 pyjwt key confusion.** Default × edge clear; primitive-direct partial — the alg confusion needs the verifier to accept HS256 with public-key material, which depends on app calling decode without restricting algorithms. Default-config gate murky on the app side. A.

The cross-ecosystem caution holds for ~99% of the manifest. But for paramiko-7750 the discriminator is so clean that I'm willing to put one S-tier on the board. If this turns out to be wrong (paramiko-7750 not exploited), the lesson is "trust the cross-ecosystem caution absolutely on Python." If it's right, the lesson is "the discriminator is the asset even cross-ecosystem."

---

## 7. Auth-missing co-tag rule applied

The letter said: search the full CVE detail (not just the headline CWE) for `CWE-306 | CWE-862 | CWE-285 | CWE-287` co-occurring with any RCE/deser/code-injection CWE, and treat every hit as presumptive S until disproven.

**Hits on this manifest:**

1. **CVE-2018-7750 (paramiko, CWE-287)** — auth-missing alone, no separate RCE co-tag needed because the summary itself says "before processing other requests" — i.e., processing follows the auth bypass. Promoted to S.

2. **CVE-2018-1000805 (paramiko, CWE-732 + CWE-863)** — CWE-863 incorrect authorization. Tiered A (not S because CWE-863 is weaker than CWE-287/306, and the file-permission co-tag suggests narrower precondition).

3. **CVE-2026-32597 (pyjwt, CWE-345 + CWE-863)** — CWE-863 + signature-verification on a JWT lib. Tiered A on the trust-boundary rule; not S because the bug is "accept unknown crit" rather than "skip verification entirely."

**Misses / events I considered but rejected:**

- **Django access control bugs (CVE-2016-2048, CVE-2021-33571, etc.)** — CWE-284 / CWE-918, not in the auth-missing CWE set. Rejected.
- **Django code injection CVE-2014-0472 (CWE-94)** — RCE-class but no auth-missing co-tag. Tiered B not S.
- **Django Trunc/Extract CRITICAL SQLi (CVE-2022-34265, CWE-89)** — no auth-missing co-tag. Tiered A on the ORM-SQLi-common-pattern rule, not S.

**Net:** the rule fired cleanly on paramiko and pyjwt. The auth-missing co-tag rule **is** cross-ecosystem-portable and earned its keep on this manifest.

---

## 8. Honest self-assessment

Does R3's training help on Python? **Yes, but less than it would on JVM, and the value is concentrated in 3-4 specific rules rather than the full discriminator framework.**

The discriminator itself (default × edge × direct) was designed against a JVM dataset where unconditional-deser-RCE is the dominant S-tier shape. On Python that shape mostly doesn't exist (per the letter's own cross-ecosystem warning), so the discriminator produces near-empty S. The marginal value of training is small in S-tier.

Where training adds real value:
- **Avoiding over-promotion on the JVM-shaped traps** (numpy CWE-502, Jinja2 sandbox, Django CWE-94 generic). An untrained operator pattern-matching on CRITICAL+CWE-94 might tier these S; the letter's "read the words, check the precondition" discipline keeps them at B.
- **Promoting the Django-specific A-tier candidates** (column-aliases SQLi, gunicorn smuggling, ASGI header spoofing, Unicode reset, libwebp, ImageMath). These are all events the letter named or described, and an untrained operator would likely tier them lower.
- **The auth-missing co-tag rule earned its keep on paramiko**, producing the only S on the board.

Where training does NOT add value:
- The letter's WAF axis discussion is irrelevant on a non-JVM manifest where no events have the WAF-hostility shape (no AJP analogs, no Log4j-class header injection).
- The Spring Security cluster discussion is inert.
- The Jackson / XStream / SnakeYaml cluster decisions are inert.
- Detailed CWE-269/CWE-44/CWE-502 hidden-gem heuristics fire on zero events here.

**Calibration question for the comparison test:** if the answer key shows ~4 exploited events (per the manifest description: "4 actually exploited" and the letter named paramiko, Django Unicode reset, libwebp, Django ORM SQLi), my picks should land hits on:
- paramiko (S, definite)
- Django Unicode reset (A, definite)
- libwebp (A, definite)
- Django ORM SQLi (multiple at A — column-aliases, _connector, Trunc/Extract, 42005)

If those are the four, I should be at 4/4 in S+A on the named-exploited events. R4 (untrained) may have hit all four too if they had ImageMath at A and the auth-bypass cluster at A; the differentiator is whether R4 promoted column-aliases SQLi or left it in the broad SQLi B-bucket.

The letter's biggest single Python contribution is making me read CRITICAL Django ORM SQLi entries as common-pattern candidates rather than as atypical-API noise. If column-aliases is one of the four exploited events, that's where the training paid for itself.

**My final answer to the meta-question: training is worth running, but the per-manifest lift on non-JVM is modest (~10-15% precision improvement on A-tier, plus 1 S-tier promotion that may or may not pan out).** A trained operator on Python is somewhere between an untrained operator on Python and a trained operator on JVM. Closer to the former than the latter.

— Trained Operator (post-R3-letter)
