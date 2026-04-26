# Hacker Ranking v4 — Django/Python 7-year C/H universe (181 events)

Operator brief. The target is a Python web stack — Django app server, Pillow for thumbnails/uploads, urllib3/requests/httpx for outbound, gunicorn or uvicorn fronting, paramiko somewhere admin-side, cryptography under TLS/JWT, jinja2 for templates, sqlalchemy if there's a non-ORM service, pyjwt for token auth, numpy buried in a data path. Not a Spring shop. Different attack physics.

I'm calling tiers from primitive mechanics. CWE labels are a starting point, not the verdict — they mislabel constantly. The S-tier shape from rounds 1-3 was *default-config × network-edge × primitive-direct*. Translating that to Python: the platonic deserialization-RCE gadget chain doesn't exist here, but the three axes still hold. What changes is what counts as a "direct primitive" — for a Python webapp, the cleanest primitives are SQLi against the ORM's stable parser surface, auth-bypass in code that runs before authn checks, and template/expression-injection that escapes a sandbox. Memory corruption in image libraries looks like S-tier on paper but the realistic exploit is unreliable — call that out below.

I am explicitly **not** consulting KEV, EPSS, breach reports, Metasploit, or marketing names. Pure mechanics.

---

## Per-event / per-cluster tiering

### Django SQLi cluster (the round-2 trap pattern)

These are the DI-tagged ones from the dataset's setup. The historical Django pattern: SQLi exists, but reaching it requires the application to pass attacker-controlled data into a specific atypical ORM API (e.g., `QuerySet.extra(...)`, raw `order_by` with user input, `Trunc`/`Extract` lookup names from request, JSON `HasKey` paths, column aliases). Most Django shops never expose those surfaces. Default-config: no. Reliable: only if the app pattern matches.

- **CVE-2019-14234** (Django, JSONField key transform SQLi) — **B**. Needs JSONField filter with attacker-controlled key. Real but conditional.
- **CVE-2020-7471** (Django StringAgg delimiter SQLi) — **B**. Needs `StringAgg(delimiter=user_input)`. Niche.
- **CVE-2020-9402** (Django GIS Oracle SQLi) — **C**. GIS + Oracle. Almost nobody.
- **CVE-2021-35042** (Django QuerySet `order_by` SQLi) — **A**. This one is the cleanest of the cluster: many apps pipe `?sort=` into `order_by`. Stable primitive, network-edge surface, default-config-likely if the app uses sortable list views. The lift here vs. the rest of the cluster is the surface ergonomics.
- **CVE-2022-28346** (Django `QuerySet.annotate/aggregate/extra` SQLi) — **B**. `extra()` / dict-key surface. Conditional.
- **CVE-2022-28347** (Django `RawSQL` annotation SQLi) — **C**. Requires the app to splice user input into `RawSQL`. If they did that they were already cooked.
- **CVE-2022-34265** (Django `Trunc()`/`Extract()` SQLi) — **A**. `kind`/`lookup_name` reachable from request data in calendar/filter views. Common shape; clean SQLi when present.
- **CVE-2024-42005** (Django QuerySet.values/values_list SQLi) — **A**. Hits a fairly normal call pattern. Direct DB primitive.
- **CVE-2024-53908** (Django HasKey JSONField on Oracle) — **C**. Oracle-only narrows surface.
- **CVE-2025-57833** (Django column aliases SQLi) — **A**. Aliases reach via `annotate()`/`values()` which apps do build dynamically; clean primitive.
- **CVE-2025-59681** (Django column aliases SQLi, distinct CVE) — **A**. Same shape as above.
- **CVE-2025-64459** (Django `_connector` kwarg SQLi in QuerySet/Q) — **A**. The `_connector` kwarg is a dunder-style internal that the ORM exposes; if request data flows into `Q(**user_dict)`, you have direct injection. Untrusted-kwargs pattern is common in dynamic filter builders.
- **CVE-2026-1207** (Django SQLi) — **B**. Insufficient detail; default to the cluster mean.
- **CVE-2026-1287** (Django SQLi) — **B**. Same.
- **CVE-2014-0474** (Django MySQL injection in aggregates) — **B**. Old, MySQL-specific.

Cluster summary: SQLi is the platonic Python-web direct primitive (no class-loader theatre needed) but **Django ORM SQLi is gated by atypical API usage**. The few that hit common request-flow patterns (`order_by`, `Trunc`/`Extract`, column-alias-via-`values`, `_connector`, `values_list`) are A-tier campaign material. The rest are B/C because exploit reach depends on app code shape that you can't assume.

### Django auth/access-control/path-traversal/CSRF/info-leak

- **CVE-2011-0696** (Django CSRF) — **D**. Old, fixed everywhere.
- **CVE-2011-4140** (Django CSRF) — **D**.
- **CVE-2011-4137** (Django DoS) — **D**.
- **CVE-2011-0698** (Django path traversal in `i18n`) — **C**. Old; few real installs.
- **CVE-2010-4534** (Django query-string handling) — **D**.
- **CVE-2018-6188** (AuthenticationForm info leakage) — **C**. Username enumeration class. Useful for post-recon, not for primary kill.
- **CVE-2019-3498** (Django input validation) — **D**. Vague, low impact.
- **CVE-2019-19118** (Django unintended model editing) — **C**. Admin-context.
- **CVE-2019-19844** (Django password-reset account hijack via Unicode-normalization on email) — **A**. This is the hidden gem of the dataset. CWE-640 "weak password recovery" sounds boring; the actual primitive is *register `me@gmail.com` as `ME@gmaıl.com` (dotless-i), trigger reset for the real address, receive the token at your account because Django case-folded/normalized the email lookup before mapping back to the user*. **Default-config × network-edge × direct full-auth bypass.** Doesn't need an authenticated session to start. The only S-tier candidate I'd genuinely entertain in this dataset, and the reason I'm S-not-A is the gating: needs the target to use `email` for reset (most do) and an attacker-registered lookalike email at the same provider (cheap but not free). I'll keep it at A because of the small but real prep step. If reset paths universally feed off email, push it to S.
- **CVE-2020-13254** (cache-key collision data leak) — **C**. Memcached config-specific.
- **CVE-2020-24583** (incorrect default file permissions) — **C**. Local exposure.
- **CVE-2021-31542** (path traversal during file upload) — **B**. Path traversal in upload handler. Reachable on any file-upload endpoint. Decent campaign material if target accepts uploads; gated by file-write-then-execute logic (not a one-shot RCE).
- **CVE-2021-33571** (SSRF via validators, "RFI/LFI") — **B**. Real SSRF surface but requires app to fetch URLs derived from validated input. Conditional.
- **CVE-2022-36359** (reflected file download) — **D**. Browser-side trick; needs user click and target download.
- **CVE-2024-39330** (Django path traversal) — **B**. Storage backend path traversal. Same shape as 2021-31542.
- **CVE-2023-31047** (multi-file upload validation bypass) — **B**. Uploads bypass — chains into RCE only if downstream handler is permissive.
- **CVE-2007-0404** (ancient "Arbitrary Code Execution") — **D**. Insufficient detail; CWE-empty; pre-historic.
- **CVE-2009-2659** (Django admin path traversal) — **C**. Old.
- **CVE-2008-3909** (Django CSRF) — **D**.
- **CVE-2014-3730** (open redirect) — **D**. Phishing aid.
- **CVE-2014-1418** (Django cache poisoning, CRITICAL severity) — **C**. Sounds nasty, primitive is `Vary` mishandling — needs cache infra in the path, not direct.
- **CVE-2014-0473** (cached CSRF token reuse) — **C**.
- **CVE-2014-0472** ("Code Injection in Django", CRITICAL CWE-94) — **B**. Trap-flavored: CWE-94 oversells. Reading the historical fix, this is an import-of-arbitrary-module surface — direct only if the app exposes user-supplied module names to a Django function that imports them. Conditional.
- **CVE-2013-4315** (`ssi` template tag directory traversal) — **C**. Template-engine knob most apps don't enable.
- **CVE-2014-3007** is Pillow (separate, see image cluster).
- **CVE-2012-3442** (Django data-URL redirect open redirect, CRITICAL severity) — **D**. Critical severity oversells; primitive is open redirect.
- **CVE-2016-7401** (CSRF protection bypass) — **C**. Specific gating.
- **CVE-2016-9013** (Django test runner hardcoded password on Oracle, CRITICAL) — **D**. Trap. Dev/test environment only.
- **CVE-2016-9014** (Django DNS rebinding, CRITICAL) — **C**. Targets users on debug-mode dev servers. Production-irrelevant.
- **CVE-2016-2048** (Django session-storage access bypass) — **C**.
- **CVE-2014-0481** (DoS via upload naming) — **D**.
- **CVE-2014-0480** (URL validation) — **D**.
- **CVE-2011-4138** (CSRF via URL verification) — **D**.
- **CVE-2011-4139** (cache poisoning) — **C**.
- **CVE-2012-4520** (arbitrary URL generation) — **D**. Misleading.
- **CVE-2015-5144** (HTTP response splitting) — **C**. Header CRLF — situational chain.
- **CVE-2026-3902** (Django ASGI header spoofing via underscore/hyphen conflation) — **A**. CWE-290 authentication-bypass-by-spoofing. The primitive: `HTTP_X_FORWARDED_FOR` and `HTTP_X-FORWARDED-FOR` collapse to the same WSGI/ASGI key, letting an attacker spoof headers that the framework trusts as "set by the proxy." If the app reads any trust-decision header from request meta — auth-token forwarders, real-IP, cluster-routing, SSO assertions, "you're already authenticated upstream" flags — this is a direct auth bypass. Default-config × edge × primitive-direct. **Hidden-gem candidate.** I'd push this to S for shops with header-trust SSO; A as the conservative default.

### Django DoS / ReDoS / resource consumption

Treat the whole bag as **D**: CVE-2019-6975, CVE-2015-5143, CVE-2019-14232, CVE-2019-14233, CVE-2019-14235, CVE-2021-45115, CVE-2021-45116, CVE-2022-23833, CVE-2022-41323, CVE-2023-23969, CVE-2023-24580, CVE-2023-36053, CVE-2023-43665, CVE-2023-46695, CVE-2024-24680, CVE-2024-39614, CVE-2024-38875, CVE-2025-64458, CVE-2026-25673, CVE-2026-33034, CVE-2007-5712, CVE-2009-3695, CVE-2013-1443, CVE-2012-3443, CVE-2012-3444, CVE-2015-2316, CVE-2015-0222, CVE-2015-0221, CVE-2015-5145.

Reasoning: DoS is C/D for an exploitation operator — disrupts but doesn't take. The only DoS I'd promote is CVE-2026-33034 (Content-Length bypass for the upload-size limit) — it's a **B** because it's a known precondition for stacking with a memory-pressure or upload-handler bug. But on its own, still defensive value primarily.

### Pillow cluster (49 events)

Pillow's primitive is "memory corruption in image decoders." Three sub-shapes:

1. **OOB read / info disclosure** (most CWE-125): leaks process memory bytes. Useful for ASLR break, ~never a one-shot.
2. **OOB write / heap corruption** (CWE-787, CWE-120, CWE-122): the theoretical RCE primitive.
3. **DoS / resource consumption** (CWE-400, CWE-770, CWE-1333, CWE-409): denial of service.

The exploit-feasibility question for Pillow heap corruption: in CPython, you have to land a useful corruption in a hostile allocator state, defeat ASLR, defeat libc/libwebp/libjpeg compile flags (modern distro builds have stack canaries, FORTIFY, often heap quarantine), and do it through the Python wrapper that re-allocates objects between your write and any meaningful read. The realistic outcome is `SIGSEGV` 95%+ of the time. Reliable RCE in a Pillow heap-corruption needs either (a) a same-binary aux primitive to chain, or (b) the corruption to land in a libwebp/libjpeg structure with a known weaponization recipe.

That puts most of Pillow in **C/D** for production weaponization. Exceptions:

- **CVE-2023-4863** (Pillow → libwebp BuildHuffmanTable OOB write) — **A**. This is the well-known underlying-C-library bug, hitting libwebp's Huffman table builder. Different from Pillow-internal Python C extensions because libwebp is shared with browsers/Electron/many native apps and the corruption shape is well-characterized. The exploitation pattern (shape-control via crafted WebP, write-out-of-bounds into a known structure) has been worked out at the libwebp layer. Default-config (Pillow opens WebP by default), network-edge (any avatar/profile-image upload), primitive-direct (OOB write in a known shape). Strong A; arguable S.
- **CVE-2022-22817** (Pillow ImageMath arbitrary-expression injection, CRITICAL CWE-74) — **A**. This is *not* memory corruption — it's `eval()`-style code execution if the app passes user input as the expression. CWE-74 understates it; the actual primitive is `ImageMath.eval(user_input, ...)` reaching `eval()`. If the target uses ImageMath at all (some image-processing pipelines do for color/channel math), this is a one-shot RCE. Conditional on use, but direct when present.
- **CVE-2023-50447** (Pillow Arbitrary Code Execution via PIL.ImageMath, CWE-94/95) — **A**. Same shape as 2022-22817 (incomplete-fix follow-up). Same gating, same A-tier.
- **CVE-2014-3007** (Pillow command injection, CRITICAL CWE-78) — **A**. Pillow shells out to `gs` (GhostScript) for EPS via `os.system`-style. If user uploads EPS and target has GS installed, command injection. Default-config-ish (EPS handler is enabled by default), network-edge (uploads), direct (command injection). Highly conditional on (a) GS installed, (b) EPS allowed in pipeline.
- **CVE-2024-28219** (Pillow buffer overflow CWE-120/676/680) — **B**. Buffer-overflow class, Pillow-internal C. Heap-corruption, low reliability.
- **CVE-2025-48379** (Pillow BCn encoding write buffer overflow CWE-122) — **B**. Same shape.
- **CVE-2026-25990** (Pillow PSD OOB write) — **B**. Same.
- **CVE-2021-25289**, **CVE-2021-25290**, **CVE-2020-35654**, **CVE-2020-5311**, **CVE-2021-34552**, **CVE-2020-5312**, **CVE-2016-2533**, **CVE-2016-0775**, **CVE-2016-4009**, **CVE-2016-3076**, **CVE-2010-4534**, **CVE-2020-10379**, **CVE-2022-30595** — all **B/C**. Heap-corruption-class in Pillow's own decoders. Plausible-but-unreliable RCE, more realistic as crash primitives.
- **CVE-2016-9190** (Pillow "arbitrary code via crafted image", CWE-284) — **B**. Vague summary; CWE-284 (improper access control) doesn't fit "code execution." Either this is the same ImageMath/eval shape or a pre-validation flaw enabling later corruption. Conservative B.
- **CVE-2014-1932** (PIL/Pillow tmp-file symlink) — **C**. Local TOCTOU.
- **CVE-2022-24303** (Pillow path traversal) — **B**. Reachable if app passes user-controlled filenames through Pillow's save path. Conditional.
- **All Pillow OOB-read entries** (CVE-2020-5313, CVE-2020-11538, CVE-2020-10177, CVE-2020-10994, CVE-2020-35653, CVE-2021-25291, CVE-2021-25293, CVE-2021-25287, CVE-2021-25288, CVE-2020-10378) — **C**. Info leak only without a chain partner.
- **All Pillow DoS / resource exhaustion** (CVE-2019-16865, CVE-2019-19911, CVE-2021-27921, CVE-2021-27922, CVE-2021-27923, CVE-2021-23437, CVE-2021-28675, CVE-2021-28676, CVE-2021-28677, CVE-2014-3589, CVE-2014-9601, CVE-2014-3598, CVE-2022-45198, CVE-2022-45199, CVE-2023-44271, CVE-2026-40192) — **D**. DoS only.

### Pillow CWE-empty / oddballs

- **CVE-2014-3598** (DOS in Jpeg2KImagePlugin, CWE empty) — **D**.

### Cryptography (pyca, 9 events)

- **CVE-2018-10903** (GCM tag forgery, CWE-20) — **A**. CWE-20 understates — this is a primitive crypto break in the AEAD verification path. If the target uses pyca-cryptography for AES-GCM with attacker-supplied tags (TLS, JWT, message verification, custom protocols), tag forgery breaks integrity outright. Network-edge if the lib is on a verification path. Conditional A; promotion to S possible if the app verifies attacker-supplied AEAD ciphertexts.
- **CVE-2020-25659** (Bleichenbacher RSA timing) — **C**. Timing oracle. Real but slow, requires many oracle queries; not campaign-scale.
- **CVE-2020-36242** (integer overflow in symmetric encrypt) — **C**. Requires user supplying multi-GB plaintexts.
- **CVE-2023-0286** (vulnerable OpenSSL bundled in wheels) — **B**. This is bundled OpenSSL X.400 type confusion — when cryptography uses certificate parsing on attacker-supplied certs (TLS client cert, smart-card auth, signed JWT/JWS chains), heap corruption in OpenSSL parser. Reaching it through pyca requires the right code path. B.
- **CVE-2023-38325** (mishandles SSH certificates) — **C**. Signature/cert validation issue. App-specific reach.
- **CVE-2023-50782** (Bleichenbacher timing oracle) — **C**. Same as 2020-25659.
- **CVE-2024-26130** (NULL deref in pkcs12 serialize) — **D**. Local crash.
- **CVE-2016-9243** (improper input validation, CWE-20) — **D**. Vague.
- **CVE-2026-26007** (subgroup attack on SECT curves) — **B**. Real crypto break — invalid-curve attack against ECC over binary fields. Requires the app to do scalar multiply on attacker-supplied SECT curve points. If the target uses SECT curves (rare, but some legacy SSH/TLS configs), full key recovery. Conditional B; A if SECT curve usage confirmed.

### urllib3 (8 events)

- **CVE-2018-20060** (cross-host header leak, CRITICAL) — **B**. Only matters if target makes outbound requests to attacker-controlled hosts. Information-class primitive.
- **CVE-2019-11324** (cert validation) — **B**. CA-list mishandling. Affects any outbound HTTPS the target makes.
- **CVE-2020-7212**, **CVE-2021-33503** (ReDoS in URL parser) — **D**.
- **CVE-2023-43804** (Cookie not stripped on cross-origin redirect) — **B**. Outbound-side credential leak. Conditional.
- **CVE-2025-66471**, **CVE-2025-66418**, **CVE-2026-21441** (decompression bombs / unbounded chains) — **C/D**. Decompression-DoS class; CVE-2026-21441 is a redirect-bypass of the safeguard, which is meaningfully worse — **B**.

### paramiko (4)

- **CVE-2018-7750** (auth bypass — process other requests before auth, CRITICAL CWE-287) — **A**. **Hidden-gem candidate.** This is the sshd-server-side equivalent of "framework processes request before checking auth." If the target runs `paramiko.ServerInterface` (admin SSH gateway, programmable jump host, file-transfer SaaS, CI worker SSH endpoint), an unauthenticated attacker can drive privileged channel-open / shell-exec-style requests. Default-config × network-edge × full auth bypass. The only thing keeping it from S is that paramiko-as-server is less common than paramiko-as-client.
- **CVE-2018-1000805** (auth bypass, CWE-732/863) — **A**. Same shape — server-side authorization bypass. Same logic, same tier.
- **CVE-2022-24302** (race condition) — **C**. Local key-file race.
- **CVE-2008-0299** (unsafe randomness) — **D**.

### pyjwt (3)

- **CVE-2017-11424** (key confusion) — **A**. The classic alg-confusion primitive: HS256-vs-RS256 surface where attacker swaps the algorithm and signs with the public key as HMAC secret. If the target uses pyjwt to verify tokens with `algorithms` not pinned, full token forgery. Network-edge (any JWT-protected API), default-config-likely if the app's JWT setup is naive, primitive is direct full auth bypass. **A leaning S.**
- **CVE-2022-29217** (key confusion via non-blocklisted public key formats) — **A**. Same shape, follow-up. Same tier.
- **CVE-2026-32597** (PyJWT accepts unknown `crit` header extensions) — **B**. CWE-345/863 — claim verification bypass via unknown crit headers. The primitive is "JWT with `crit: ["nope"]` is accepted instead of rejected, defeating downstream extension-based security checks." If the target relies on JWS critical extensions, full bypass; if not, minor. Conditional B.

### jinja2 (3)

- **CVE-2019-10906** (sandbox escape via str.format_map) — **A**. Sandbox escape primitives are direct RCE *if* the target runs untrusted templates through the sandbox. The use case is rare (most apps don't render attacker templates) but when present, this is one-shot. Conditional A.
- **CVE-2016-10745** (sandbox escape via `%`-formatting) — **A**. Same shape, same tier.
- **CVE-2014-1402** (incorrect privilege assignment, CWE-266) — **C**. Tmpdir/permissions class.

### sqlalchemy (3)

- **CVE-2019-7548** (`group_by` SQLi, CRITICAL) — **A**. SQLAlchemy SQLi has the same gating as Django ORM — needs the app to pipe user input into `group_by`. When present: direct DB primitive.
- **CVE-2019-7164** (`order_by` SQLi, CRITICAL) — **A**. Common pattern; many apps do `?sort=` → `order_by(user_input)`. Strong A.
- **CVE-2012-0805** (SQLAlchemy SQLi) — **B**. Old; gated similarly.

### gunicorn (3)

- **CVE-2018-1000164** (CRLF injection in HTTP headers) — **B**. Header injection — splitting/smuggling primitive, useful as chain.
- **CVE-2024-1135** (request smuggling) — **A**. Smuggling against the stock Python WSGI gateway. If gunicorn is fronted by a proxy that disagrees about request boundaries, the operator pushes a hidden request past WAF/auth. Default-config-likely (gunicorn behind nginx/ALB is the canonical Python deploy), edge, primitive is bypass-of-perimeter-auth-or-WAF. Strong A; pushes S in shops with auth at the proxy layer.
- **CVE-2024-6827** (gunicorn smuggling) — **A**. Same shape, follow-up.

### flask (3)

- **CVE-2018-1000656** (DoS via JSON encoding) — **D**.
- **CVE-2019-1010083** (DoS unexpected memory usage) — **D**.
- **CVE-2023-30861** (permanent session cookie disclosure via missing Vary: Cookie) — **C**. Cache-edge condition.

### numpy (5)

- **CVE-2019-6446** (Deserialization of untrusted data, CRITICAL CWE-502) — **B**. `numpy.load(allow_pickle=True)` reaches `pickle.load`. Direct one-shot RCE *if* the app does that on attacker data. Conditional. The "newer numpy makes this opt-in" mitigation is doing most of the work; B.
- **CVE-2017-12852** (CWE-835 infinite loop) — **D**.
- **CVE-2021-41495** (NULL deref) — **D**.
- **CVE-2014-1859** (symlink arbitrary file write) — **C**. Local TOCTOU.
- **CVE-2014-1858** (arbitrary file write) — **C**. Local.

### Other one-offs

- **CVE-2018-18074** (requests credentials leak via redirect) — **B**. Outbound-only; condition on target making auth'd outbound calls.
- **CVE-2020-7694** (uvicorn log injection) — **D**.
- **CVE-2020-7695** (uvicorn HTTP response splitting) — **C**. Reachable if app pipes user input into response headers.
- **CVE-2020-15225** (django-filter NumberFilter DoS) — **D**.
- **CVE-2020-35681** (channels session leak) — **C**. Legacy-handler specific.
- **CVE-2021-30459** (django-debug-toolbar SQLi) — **D**. Debug-toolbar is dev-only; if it's exposed in prod the target had bigger problems already, but it's not a realistic campaign primitive.
- **CVE-2021-23727** (celery OS command injection) — **B**. CWE-77/78 looks S, but reach requires the target to pass user input into celery task names/payloads in a way that hits the broker injection — conditional. If present, direct RCE.
- **CVE-2021-41945** (httpx improper input validation) — **D**.
- **CVE-2023-28117** (sentry-sdk session info leak) — **D**.
- **CVE-2023-28859** (redis-py race condition) — **D**.
- **CVE-2026-32274** (black: arbitrary file writes from cache filename) — **D**. Black is dev-tool. Not in production attack surface.

---

## Summary

### 1. Tier counts (cluster-aware)

| Tier | Count | Notes |
|------|------:|-------|
| S    | 0     | Nothing meets all three axes cleanly. CVE-2019-19844 (Django reset hijack) is the closest; CVE-2026-3902 (ASGI header spoof) is the dark-horse second. Both are conservatively held at A. |
| A    | ~17   | The actually-actionable list — see below. |
| B    | ~30   | Conditional-on-app-shape primitives. Worth fingerprinting before campaign commit. |
| C    | ~30   | Situational, chain-only, or local-context. |
| D    | ~104  | DoS bag (~41), CSRF/info-leak/old/dev-only/admin-context. The Pillow OOB-read sub-bag and most non-libwebp Pillow heap-corruption land here for *campaign* purposes. |

(Counts are cluster-aware approximations from the per-event walk above; the dominant signal is the D-bag because of the DoS skew and the Pillow info-leak/heap-crash sub-clusters.)

### 2. Top weaponization picks (ordered)

1. **CVE-2019-19844** — Django password reset Unicode hijack. Direct full-auth-takeover via attacker-controlled lookalike email. Default-config Django, network-edge reset endpoint, primitive is one-shot account capture. The only event in the dataset that genuinely walks like S — held at A only because of the lookalike-registration setup step.
2. **CVE-2018-7750** / **CVE-2018-1000805** — paramiko server-side auth bypass. If the target runs paramiko `ServerInterface` (CI/jump host/SaaS file gateway), unauthenticated attacker drives post-auth channel operations. Same primitive shape as the Spring SecurityContext / framework-processes-before-auth bugs from rounds 2-3.
3. **CVE-2017-11424** / **CVE-2022-29217** — pyjwt key confusion / alg confusion. JWT-protected APIs with naive verifier configs → full token forgery. Direct, edge, default-likely.
4. **CVE-2024-1135** / **CVE-2024-6827** — gunicorn HTTP request smuggling. WAF/auth-at-proxy bypass against the canonical Python deploy stack.
5. **CVE-2023-4863** — Pillow → libwebp BuildHuffmanTable. The one Pillow heap-corruption with a known shape and credible weaponization pathway. Network-edge (avatar uploads), default-config (WebP enabled).
6. **CVE-2025-64459** / **CVE-2025-57833** / **CVE-2025-59681** / **CVE-2024-42005** / **CVE-2022-34265** / **CVE-2021-35042** — the cleanest Django ORM SQLi reach patterns (`_connector` kwarg, column aliases, `Trunc`/`Extract`, `order_by`, `values_list`). Each gates on a common app pattern; line up the target before committing.
7. **CVE-2026-3902** — Django ASGI header spoofing. If the target trusts proxy-set headers for authn/IP/SSO, this is full bypass. CWE-290 labels it correctly as auth-bypass-by-spoofing.
8. **CVE-2019-7164** / **CVE-2019-7548** — SQLAlchemy `order_by`/`group_by` SQLi for non-Django Python services in the same target.
9. **CVE-2022-22817** / **CVE-2023-50447** — Pillow ImageMath eval. Conditional on usage but a one-shot RCE when present.
10. **CVE-2019-10906** / **CVE-2016-10745** — Jinja2 sandbox escape, conditional on the target rendering attacker templates through `SandboxedEnvironment`.

### 3. Trap picks — CRITICAL severity that I'm tiering low

- **CVE-2018-7750** is CRITICAL and I'm holding A only because paramiko-as-server is a deployment-shape question — not a trap; flag it for fingerprinting first.
- **CVE-2014-0472** ("Code Injection in Django", CWE-94, CRITICAL) — **B trap-flavor**. Sounds like RCE; primitive is conditional on app feeding user input into module-import paths. Most apps don't.
- **CVE-2016-9013** (Django Oracle test runner hardcoded password, CRITICAL) — **D trap**. Test-environment artifact.
- **CVE-2016-9014** (Django DNS rebinding, CRITICAL) — **C trap**. Targets dev runserver, not prod.
- **CVE-2014-1418** (Django cache poisoning, CRITICAL) — **C trap**. Primitive is `Vary` mishandling; reach depends on cache infra, not direct.
- **CVE-2012-3442** (Django open redirect via data URL, CRITICAL) — **D trap**. Severity oversells phishing aid.
- **CVE-2018-20060** (urllib3 cross-host header leak, CRITICAL) — **B**. Outbound-only and information-class.
- **CVE-2019-6446** (numpy pickle, CRITICAL CWE-502) — **B**. Looks like a deserialization-RCE one-shot, but `allow_pickle=True` opt-in mitigation kills the default-config path. The Spring/Java equivalent would be A; in Python it's B because the dangerous default is gone.
- **CVE-2019-7164** / **CVE-2019-7548** / **CVE-2012-0805** — SQLAlchemy SQLi labeled CRITICAL; tiered A/B by shape because reach depends on app code.
- **CVE-2021-34552** / **CVE-2020-5311** / **CVE-2020-5312** / **CVE-2025-64459** / **CVE-2014-3007** / **CVE-2020-11538** etc. — multiple Pillow CRITICALs. Most are heap-corruption with low real-world reliability or (3007) shell-out gated on GhostScript install. The CRITICAL label for memory-corruption-in-image-libraries is largely about *severity-if-exploited*, not *exploit-feasibility*. Operator should discount accordingly.
- **CVE-2014-0481** / **CVE-2014-0480** / **CVE-2008-3909** / **CVE-2011-0696** / etc. — old HIGH/CRITICAL CSRF/DoS/redirect — defensive-impact only.

### 4. Hidden-gem picks — CWE/severity undersells

- **CVE-2019-19844** — labeled CWE-640 "weak password recovery." Sounds boring; *primitive is a unicode-normalization auth bypass that hands you a reset token to an account you don't own.* This is the dataset's strongest play and the CWE undersells it badly.
- **CVE-2026-3902** — labeled CWE-290. Many people read CWE-290 as "spoofing, eh, header-trust issues." The actual primitive is *trust-boundary-confusion in the ASGI header normalizer*: if the framework conflates `_` and `-` in header names, an external client can synthesize a "trusted" proxy header that bypasses authn/SSO/IP-allow-list logic. Direct full bypass when the trust pattern is present.
- **CVE-2018-7750** / **CVE-2018-1000805** — paramiko auth bypass tagged CWE-287/863. The Python equivalent of the Spring framework-processes-before-auth pattern that round 2 nailed. If the target runs paramiko-as-server anywhere, this is one-shot.
- **CVE-2018-10903** — pyca GCM tag forgery, labeled CWE-20 "improper input validation." That label is wrong. The actual primitive is *crypto-integrity break*: anyone who hands the lib a forged tag passes verification. CWE-345 (insufficient verification of authenticity) would be the right label. JVM-trained intuition would skim past CWE-20; this is closer to A than the label suggests.
- **CVE-2017-11424** / **CVE-2022-29217** — pyjwt key confusion. CWE-empty / CWE-327 understate; this is direct full-token-forgery on naive verifiers.
- **CVE-2023-4863** — labeled CWE-787 in Pillow but the actual bug is in libwebp's Huffman table builder, shared with browsers/Electron/many apps. The exploit shape is well-characterized at the libwebp layer, which is uncommon for image-library memory corruption. The Pillow label undersells the surface: any avatar/profile-image upload path is a delivery vehicle.
- **CVE-2024-1135** / **CVE-2024-6827** — gunicorn smuggling labeled CWE-444. The unsexy CWE is the same one that gets ignored in defender prioritization for proxy stacks; for an operator with a target running a perimeter WAF or proxy-layer authn, smuggling against gunicorn bypasses both at once.

### 5. Memory-corruption-in-image-libraries — discriminator within the Pillow cluster

The 49 Pillow events split:

- **OOB read / info disclosure (~14)** — by themselves, low-value primitives. Information leak from worker process. **C** for chain-into use, **D** as primary primitive.
- **OOB write / heap corruption / buffer overflow (~14)** — the theoretical RCE class. The reality:
  - Modern CPython processes have ASLR, often run with hardened-malloc or jemalloc, and the Pillow C extensions are typically compiled with FORTIFY_SOURCE on distro builds.
  - Triggering corruption is easy. Turning it into reliable RCE inside CPython's allocator dance is hard.
  - Realistic outcome: 90%+ crash, occasional info-leak chain, rare RCE. Reliable-enough-for-campaigns RCE typically requires a same-binary aux primitive or a known weaponization recipe at the underlying C library layer.
  - That puts most of these at **B** for chain-into, **C** as standalone. The exception is **CVE-2023-4863 (libwebp BuildHuffmanTable)** at **A** because the underlying bug is shared with browsers and the weaponization is characterized at the libwebp layer, not the Pillow Python wrapper.
- **DoS / decompression bombs / ReDoS (~17)** — **D** for an exploitation operator. Defender problem.
- **Path traversal / TOCTOU / odd CWEs (~4)** — **B/C**, depends on app pipeline.
- **The two ImageMath eval bugs (CVE-2022-22817, CVE-2023-50447)** — **A**, but these are *not* memory corruption — they're function-eval injection. Worth pulling out of the cluster mentally because the primitive is fundamentally cleaner (one-shot RCE if the eval surface is reached) than any heap-corruption.

So the discriminator within Pillow: **eval-class > underlying-C-library-with-known-shape (libwebp) > Pillow-internal-C-OOB-write > OOB-read > DoS**. "CWE-787 in a network-reachable image processor" is **not S-tier** as a general statement in 2026 — the realistic exploit shape is too unreliable for production weaponization without a chain partner or a libwebp-style underlying-library shape.

### 6. The discriminator check — does default-config × network-edge × primitive-direct still apply?

It applies, but with two adjustments for Python:

**What stays the same.** The three-axis model still works as a tier-assignment frame. CVE-2019-19844 (reset hijack) hits all three. So does CVE-2026-3902 (ASGI header spoof) when the target trusts proxy headers. So would CVE-2017-11424 / CVE-2022-29217 (JWT alg confusion) on naive JWT setups. So would CVE-2018-7750 on a paramiko-server target. The primitives are different from JVM but the axes still cut signal from noise.

**What strains.** "Primitive-direct" had a clean meaning in JVM — deserialization-RCE gadget chain, JNDI lookup, class-loader attack. In Python the equivalent direct primitives are:

1. **Direct ORM/DB SQLi** when the dynamic-API surface is reached. Cleaner than JVM SQLi because there's no escape-by-default convention to second-guess.
2. **Auth-flow bypass in pre-authn code paths.** The paramiko-server bugs are the platonic example.
3. **Token-forgery via signature verification weakness.** JWT alg-confusion, GCM tag forgery, JWS crit-extension bypass.
4. **Template/expression-injection escaping a sandbox.** Jinja2 sandbox escape, ImageMath.eval.
5. **Request smuggling at the WSGI/ASGI gateway.** gunicorn smuggling.

What you do **not** get in Python is the platonic JVM "untrusted-bytes-in-cookie → full RCE" shape. Python's `pickle.load` would give you that, but mature libs (numpy is the example here) made `allow_pickle=True` opt-in, killing the default-config axis. There's no Python-ecosystem-wide gadget-chain library equivalent to ysoserial/Marshalsec — the language has the primitive but the deployment surface for it is much narrower.

**Where JVM-trained reasoning would miss.** Two Python-native S-shapes that JVM-trained instinct undervalues:

1. **Unicode-normalization / canonicalization auth bypasses.** Python's mature Unicode/email handling makes these viable in places JVM apps generally don't expose. CVE-2019-19844 is the example. Look for any auth-flow lookup that case-folds or normalizes before mapping to a user record.
2. **Header-name normalization in WSGI/ASGI.** Django/CGI's underscore-hyphen conflation has been a recurring class for decades. CVE-2026-3902 is the current example. JVM servlet containers don't have this problem because the Servlet API uses raw header names; WSGI's `HTTP_*` env-var mangling does. JVM-trained intuition would skip this CWE-290; in Python it's a direct bypass when present.

I'd add: **token-verification semantic bypasses** (pyjwt crit, GCM tag forgery, libwebp Huffman OOB) deserve more weight than CWE labels suggest because Python apps tend to centralize trust decisions in a small number of widely-used libraries, so a single library bug becomes a cross-tenant primitive faster than the JVM equivalent.

### 7. Cross-ecosystem comparison vs. round 3

**Round 3 Spring/Java had clean S-tier:** Log4j JNDI, ActiveMQ deser-RCE, Tomcat/AJP, Spring Cloud Function expression injection. Each of those: default-config, network-edge, one-shot RCE primitive. The S-tier was *populated* and the primitives were *direct*.

**This Django/Python dataset has no genuine S.** The closest events are:

- CVE-2019-19844 (Django reset hijack) — three-axis-clean, gated only by the lookalike-email registration step. **A → S-defensible**.
- CVE-2026-3902 (Django ASGI header spoof) — three-axis-clean *when the target trusts proxy headers*. **A → S-defensible** in trust-header SSO shops.
- CVE-2018-7750 / CVE-2018-1000805 (paramiko) — three-axis-clean *when paramiko runs server-side*. **A**.
- CVE-2017-11424 / CVE-2022-29217 (pyjwt alg confusion) — three-axis-clean *when JWT verifier doesn't pin algorithms*. **A**.

Each is gated on a deployment-shape question. None is the unconditional default-config win that Log4j was.

**Why is the S-tier empty?** Three reasons, in order of importance:

1. **Python's fastest one-shot-RCE primitive (`pickle.load` on untrusted bytes) was killed at the library default.** numpy made it opt-in, the broader ecosystem learned the lesson. The Spring/Java equivalent (deserialization gadget chains) was *not* killed at the default — Spring/Tomcat keep shipping ObjectInputStream-on-the-wire patterns. So the Python ecosystem genuinely has fewer one-shot-RCE primitives by default. **Real signal.**

2. **The manifest is missing the usual high-priority Python attack surfaces.** Notably absent: Werkzeug `debug=True` PIN bypass, any CGI-handler shell-injection (Apache mod_python-style), python-yaml `Loader=Loader` issues (PyYAML isn't in the manifest), pickle-RPC servers (xmlrpc/celery's worker-side pickle deserialization isn't represented as the in-the-wild critical). Flask itself only contributes 3 events, none of which are routing or debug-mode bugs. Gunicorn is here but uvicorn only twice. The actual Python production-ops attack surface — the PIN bypass class, YAML loader class, debug-server class — is under-sampled. **Manifest selection effect, not ecosystem reality.**

3. **The S-tier shape is shifted, not absent.** Python's S-tier candidates look like (a) Unicode/canonicalization auth bypass at the framework level, (b) WSGI header normalization, (c) JWT/AEAD verification breaks. These exist in this dataset (19844, 3902, 11424, 22817 mapped to A) but they're each one deployment-shape question away from S. The discriminator's "primitive-direct" axis is doing work — these are direct primitives — but the third axis "default-config" gates more harshly in Python because *Python framework defaults have been hardened more aggressively post-Heartbleed than JVM enterprise defaults*. The Python ecosystem's decade of paranoid defaults shows up here as fewer S-tier candidates.

**The honest read.** Python production stacks are *genuinely harder* to one-shot than Spring shops because the language's two riskiest primitives (`pickle.load`, `eval()`-in-template) both had ecosystem-level mitigations, and the framework community ran a tighter ship on dangerous defaults than Spring did from 2017-2024. A 7-year manifest of Spring C/H gave round 3 four or five clear S candidates because the language and frameworks shipped with foot-guns. The same manifest scope on Django/Python gives zero unconditional S. That's not an artifact of the discriminator — *the discriminator correctly identifies that nothing here is unconditionally one-shot*. The pickup is in the A tier, where deployment-shape fingerprinting (does the target use SSO header trust? does it run paramiko server-side? does its JWT verifier pin algorithms? does its image pipeline accept WebP?) determines which A-tier becomes the operator's S-tier for that specific target.

**Allocation guidance.** For a Python target, I'd front-load reconnaissance over exploit-write. The exploit primitives in A-tier are well-characterized (each is documented at the library level). The campaign delta vs. JVM is that the recon investment to determine *which A-tier becomes the kill shot* is bigger than the recon investment for JVM, where Log4j-class bugs are unconditional. Budget the recon, then commit to the one A-tier that the target's deployment shape upgrades to a S-equivalent. Pillow's libwebp path (CVE-2023-4863) is the one I'd carry as a backup payload because its delivery vehicle (any avatar upload) is the most universal of the A-tier list.

---

**Bottom line for the operator.** S-tier shelf is empty as a hard verdict. A-tier shelf has ~17 entries, eight of which are unconditional kill shots if the target's deployment shape lines up. The discriminator generalizes — three axes still cut signal — but in Python the third axis ("default-config") is more demanding than in JVM, so the tier distribution skews one notch toward A and B. The CWE labels mislead more in this dataset than in Spring; the worst offenders are CWE-20 ("improper input validation") on what's actually a crypto break (CVE-2018-10903), CWE-640 ("weak password recovery") on what's actually a unicode auth bypass (CVE-2019-19844), and CWE-290 ("auth bypass by spoofing") which is read as low-stakes but is a clean direct bypass when reached (CVE-2026-3902). Trust the mechanics, not the labels.
