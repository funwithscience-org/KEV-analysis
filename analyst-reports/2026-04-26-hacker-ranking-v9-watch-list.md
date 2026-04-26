# Hacker round 9 — Exploit Watch List validation

**Date:** 2026-04-26
**Input:** The 11 events on the §12 Exploit Watch List in the walkthrough (server-side ×9 + desktop/client-side ×2). Some are already confirmed in KEV; others are still WATCHING. Goal: apply the same discriminator used in earlier rounds and see whether the watch list's selection criteria are picking the same events the offensive operator would.

**Discriminator:** Default-config × network-edge × primitive-direct, with auth-missing co-tag rule. Tier S = unconditional one-shot at default config, internet-edge, direct primitive. Tier A = strong primitive with one near-default precondition. Tier B = real precondition gates reach. Tier C = defense-in-depth or chain-into. Tier D = DoS / info-leak / weak crypto config.

## Server-side watch list

### S — unconditional one-shot RCE primitive

- **CVE-2026-21858 n8n "Ni8mare"** (CVSS 10.0) — Unauthenticated RCE via Content-Type confusion. n8n is workflow automation with ~100K exposed instances per the watch-list note. Unauth + RCE + network edge + default config + public PoC. Hits all three discriminator axes plus the auth-missing co-tag. **Tier S.** This is the canonical campaign-list event.
- **CVE-2026-39987 Marimo** (CVSS 9.3) — Missing auth on WebSocket endpoint, 662 exploit events observed Apr 11-14, KEV-confirmed Apr 23. Unauth RCE via WebSocket. **Tier S.** Matches the auth-missing co-tag rule cleanly.

### A — strong primitive at default or near-default

- **CVE-2026-40477 Thymeleaf SSTI** (CVSS 9.0) — Unauth RCE via server-side template injection. Same primitive class as Spring4Shell. Default-config (Thymeleaf is server-side default in Spring Boot apps using it), network-edge (HTTP request), direct primitive. The reach gate is whether the app routes attacker-influenced data into a template name or unsafe attribute. **Tier A.** Could promote to S in shops with confirmed `th:` attribute injection on user input.
- **CVE-2026-40478 Thymeleaf-Spring5 SSTI** (CVSS 9.0) — Paired disclosure with -40477, Spring 5 integration. Same primitive class. **Tier A.**
- **CVE-2026-20180 Cisco ISE** (CVSS 9.9) — Authenticated RCE via crafted HTTP request. Auth requirement is a real precondition but Cisco ISE deployments often ship with default service-account credentials that show up in Shodan; assume valid creds achievable. **Tier A.** Part of the four-CVE Cisco cluster (probably a Mythos participant self-scan finding).
- **CVE-2026-32201 SharePoint** (CVSS 6.5) — HTTP endpoint auth bypass, actively exploited as zero-day, KEV-confirmed Apr 14. Auth bypass on default endpoint. CVSS understates because the bypass enables broader attack chains. **Tier A.**
- **CVE-2026-34197 Apache ActiveMQ** (CVSS 9.8) — HTTP admin console / Jolokia MBean deserialization. KEV-confirmed Apr 16. R3 already rated this Tier A. **Tier A.**

### B — opportunistic, narrow precondition

- **CVE-2026-5194 wolfSSL cert validation** (CVSS 9.1) — Forged certs across ECDSA / DSA / Ed25519. Reach gates on whether wolfSSL is doing the TLS termination AND the application accepts certs from untrusted clients without additional validation. Mythos-attributed; the ~5B affected devices figure is the embedded surface. **Tier B** for typical server deployments (cert validation is one of several auth steps); **A** for embedded/IoT shops where wolfSSL is the only auth barrier.
- **CVE-2026-5501 wolfSSL OpenSSL compat** (CVSS 8.1) — Impacts NGINX/haproxy via wolfSSL compat shim. Lower CVSS but same family. The reach gate is whether the deployment actually compiled NGINX with wolfSSL instead of OpenSSL — non-default. **Tier B.**

## Desktop / client-side watch list

The hacker discriminator is server-focused (designed around NP+DI primitives reachable from the internet). Client-side bugs follow different economics — browser/desktop UAFs in particular weaponize within hours-to-days because the exploit-broker market is liquid (per §4). Tiering them on the same rubric undersells; treating them on a separate axis is more honest.

- **CVE-2026-34621 Adobe Acrobat** (CVSS 7.8) — Prototype pollution via crafted PDF, delivered via HTTP. KEV-confirmed Apr 15. Client-side exploitation chain (user opens PDF). On the server-focused discriminator: **Tier B** (client-side, requires user action). On a client-exploitation rubric: **A** (delivered via HTTP, weaponized fast).
- **CVE-2026-33825 Windows Defender "BlueHammer"** (CVSS 7.8) — Local elevation-of-privilege with public PoC. KEV-confirmed Apr 22. Used as part of browser-delivered exploit chains. On the server-focused discriminator: **Tier B** (post-compromise privilege escalation, like the OS-layer LPE bugs in §8). On a client-chain rubric: **A** (chain component for browser-delivered escalation).

## Hacker × Watch List × KEV summary

| CVE | Watch list status | Hacker tier | Notes |
|---|---|---|---|
| CVE-2026-21858 n8n | WATCHING | **S** | Hacker S; would have flagged for same campaign reasons |
| CVE-2026-39987 Marimo | KEV ✓ | **S** | KEV-confirmed; both flag |
| CVE-2026-40477 Thymeleaf | WATCHING | **A** | Both flag |
| CVE-2026-40478 Thymeleaf 5 | WATCHING | **A** | Both flag |
| CVE-2026-20180 Cisco ISE | WATCHING | **A** | Both flag |
| CVE-2026-32201 SharePoint | KEV ✓ | **A** | KEV-confirmed; both flag |
| CVE-2026-34197 ActiveMQ | KEV ✓ | **A** (prior R3) | KEV-confirmed; both flag |
| CVE-2026-5194 wolfSSL cert | WATCHING | **B** | Hacker more cautious (deployment-shape precondition) |
| CVE-2026-5501 wolfSSL compat | WATCHING | **B** | Hacker more cautious (compile-time precondition) |
| CVE-2026-34621 Adobe Acrobat | KEV ✓ | **B** server-focus / **A** client | KEV-confirmed; client-side chain |
| CVE-2026-33825 BlueHammer | KEV ✓ | **B** server-focus / **A** client | KEV-confirmed; post-compromise component |

## Watch list selection × hacker discriminator

**Strong agreement on the server-side cluster.** All 7 server-side watch-list entries that the hacker would tier S or A are also on the watch list (and 3 of those 7 are already KEV-confirmed). The hacker's stricter B tier on the two wolfSSL events is worth surfacing — they remain on the watch list because they hit the deployment-footprint criterion, but the operator would treat them as opportunistic-rather-than-priority.

**Client-side handling diverges by design.** The watch list intentionally tracks client-side / desktop CVEs because they end up in KEV via different pathways than server-side NP+DI. The hacker discriminator's server-focus B-tiers them on the campaign axis, but they're A-tier on the client-exploitation chain. This is a known limitation of the discriminator for client-side bugs.

**Hit rate so far: 5 of 11 confirmed in KEV (45%) within the first month of the watch list.** All 5 confirmations were either S/A on the server-focused discriminator OR A on the client-chain reading. Zero KEV confirmations of B-tier entries to date. This is consistent with the structural finding from earlier rounds: the discriminator's S+A tier carries most of the exploitation weight.
