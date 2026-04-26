# Hacker round 6 — Node.js/Express + Netty (12-month framework backtest)

**Date:** 2026-04-26
**Input:** `data/_hacker-input-blind-v6-node-netty-12mo.json` (20 Node events + 3 Netty events, blinded — no `is_np`/`is_di`/outcomes provided)
**Discriminator:** Same as R3/R4 — default-config × network-edge × primitive-direct, with auth-missing co-tag rule for CWE-287/289/306/693/863/1321.
**Why this round:** R3 covered the Java/Spring 175-event input (which subsumes the Spring 12-month manifest). R4 covered the Django 181-event input (which subsumes the Django 12-month manifest). Node and Netty had no prior hacker tier coverage, so this round fills the gap to enable a clean 4-framework S+A comparison on the periodicity backtest window.

## Node.js/Express manifest (20 events, Apr 2025 – Apr 2026)

### S — unconditional one-shot RCE primitive

None. No event in this 12-month set is the "log-anything-with-${jndi}" or "POST a serialized blob to a default-on endpoint" shape.

### A — strong primitive at default or near-default with internet-edge reach

- **CVE-2026-30951** sequelize CWE-89 — SQL injection via JSON column casting. ORM-layer SQLi is rare and high-value; if the app uses sequelize and passes any user-controlled value into a JSON column query (or through a `where` filter that hits JSON casting), attacker controls SQL. Sequelize is heavily deployed in Node enterprise stacks. Direct primitive, broad reach. **Tier A.**
- **CVE-2026-33937** handlebars CWE-843+94 — JS injection via AST type confusion. Server-side template injection in Handlebars → arbitrary JS execution server-side. Same primitive class as Thymeleaf SSTI in JVM. **Tier A.** Reach gates on whether the app passes attacker data into `Handlebars.compile()` or via partial names — common pattern in CMS/email templates.
- **CVE-2026-33938** handlebars CWE-843+94 — Same SSTI class. **Tier A.**
- **CVE-2026-33940** handlebars CWE-843+94 — Same SSTI class. **Tier A.**
- **CVE-2026-4800** lodash CWE-94 — Code injection via `_.template` imports. `_.template` accepting attacker-controlled template string → arbitrary JS execution. lodash is in nearly every Node project; `_.template` usage is uncommon in modern code but recurring vector when present (CVE-2021-23337 was the same shape). Direct primitive once `_.template(userInput)` is in the codebase. **Tier A.**

### B — opportunistic, narrow precondition

- **CVE-2026-27959** koa CWE-20+74 — Host header injection via `ctx.hostname`. Koa server, control over `ctx.hostname` reaches password-reset poisoning, cache poisoning, redirect smuggling. Strong primitive but not unconditional RCE; depends on what the app does with hostname. **Tier B.**

### C — defense-in-depth, MITM-needed, or ambiguous

- **CVE-2026-25223** fastify CWE-436 — Content-Type tab character allows body validation bypass. Fastify schema validator can be bypassed with leading tabs in Content-Type. Defense-in-depth weakening; reaches actual exploit only if a downstream sink trusts the schema-validated shape. **Tier C.**
- **CVE-2026-25639** axios CWE-754 — DoS via `__proto__` key. Likely prototype pollution shape — reaches RCE only via victim-side gadget. axios is the *client* library, so the server-side reach is limited. **Tier C.** (B if a clear server-side gadget chain were obvious.)
- **CVE-2026-33941** handlebars CWE-94+116+79 — JS Injection in CLI Precompiler. CLI tooling = build-time, not runtime. Reaches exploit only if attacker controls dev's local precompiler input. **Tier C.**
- **CVE-2026-33806** fastify CWE-1287 — Body schema validation bypass via leading spaces. Same shape as -25223. **Tier C.**

### D — DoS only, log injection, weak crypto config, or info leak

- **CVE-2025-47935** multer CWE-401 — DoS via memory leak. **D.**
- **CVE-2025-47944** multer CWE-248 — DoS via uncaught exception. **D.**
- **CVE-2025-48997** multer CWE-248 — DoS. **D.**
- **CVE-2025-7338** multer CWE-248 — DoS. **D.**
- **CVE-2025-58754** axios CWE-770 — DoS via lack of size limit. **D.**
- **CVE-2025-14874** nodemailer CWE-703 — Address parser regex DoS. **D.**
- **CVE-2026-2359** multer CWE-772 — DoS via resource exhaustion. **D.**
- **CVE-2026-3304** multer CWE-459 — DoS via incomplete cleanup. **D.**
- **CVE-2026-3520** multer CWE-674 — DoS via uncontrolled recursion. **D.**
- **CVE-2026-33939** handlebars CWE-754 — DoS via malformed decorator. **D.**

### Node summary

| Tier | Count | Unique trigger dates |
|---|---|---|
| S | 0 | 0 |
| A | 5 (sequelize, handlebars ×3, lodash) | 3 (2026-03-11, 2026-03-27, 2026-04-01) |
| B | 1 | 1 |
| C | 4 | 3 |
| D | 10 | 8 |

**Hacker S+A unique dates: 3** (2026-03-11 sequelize, 2026-03-27 handlebars cluster, 2026-04-01 lodash)

## Netty manifest (3 events, Apr 2025 – Apr 2026)

### A

- **CVE-2026-33870** netty-codec-http CWE-444 — HTTP request smuggling via chunked extension quoted-string parsing. Netty is widely used as a backend HTTP server with reverse proxies in front. Request smuggling reaches behind front-end proxies → bypass auth, request hijack, cache poisoning. CWE-444 is the canonical RS shape. **Tier A.**

### D

- **CVE-2025-55163** netty-codec-http2 CWE-770 — MadeYouReset HTTP/2 DDoS. **D.**
- **CVE-2026-33871** netty-codec-http2 CWE-770 — HTTP/2 CONTINUATION Frame Flood DoS. **D.**

### Netty summary

| Tier | Count | Unique trigger dates |
|---|---|---|
| A | 1 | 1 (2026-03-26) |
| D | 2 | 2 |

**Hacker S+A unique dates: 1** (2026-03-26 netty-codec-http RS)

## Cross-framework S+A roll-up (12-month, Apr 2025 – Apr 2026)

| Framework | Manifest | All C+H | NP+DI | NP+DI + AI scan | **Hacker S+A** |
|---|---|---|---|---|---|
| Spring Boot | 48 deps | 14 | 5 | 6 | **5** (R3) |
| Node.js/Express | 45 deps | 14 | 2 | 4 | **3** (R6) |
| Django/DRF | 40 deps | 14 | 6 | 7 | **4** (R4) |
| Netty | 7 deps | 2 | 1 | 1 | **1** (R6) |

Hacker S+A reductions vs all C+H: Spring 64%, Node 79%, Django 71%, Netty 50%.

## Notes on the "extra" Node + Netty events (as requested)

I was asked to actually rank these rather than predict they'd all be B/C. Result: there are 5 A-tier candidates I'd take seriously across the two manifests — sequelize SQLi, three handlebars SSTI variants, and lodash `_.template`. None reach S because none is unconditional one-shot at default config — every one of them gates on whether the application is using the affected API path with attacker-controllable input. The handlebars cluster is the most likely to bite production: SSTI in template engines tracks closely with the Spring/Thymeleaf SSTI cluster R3 caught.

The Netty request-smuggling event (CVE-2026-33870) is the kind of bug an experienced operator stays alert to even when the manifest is small — only 7 deps, but the one A-tier event is the cleanest primitive in the whole 23-event input.
