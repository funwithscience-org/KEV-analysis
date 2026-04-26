# Hacker round 8 — OS container layer (Amazon Linux 2023, ~25 components)

**Date:** 2026-04-26
**Input:** `data/_hacker-input-blind-v8-os-container.json` — 69 critical/high CVEs, 12-month window (Apr 2025 – Apr 2026), tagged with attack vector (NETWORK / LOCAL / PHYSICAL).
**Context given to hacker:** This OS manifest sits *underneath* the Java/Spring app the hacker has previously ranked. The Spring app handles all network ingress; the OS layer is reached only after the attacker is either (a) on the same network through an unrelated path or (b) already running code inside the container via an app-layer breach (Spring4Shell, Tomcat path traversal, Thymeleaf SSTI, etc.).

## First pass — clean the dataset

Before any tier ranking, the **NVD keyword-matching is generating massive noise** in this manifest. Of the 69 events, roughly 40-50 are NOT actually bugs in the OS components — they're CVEs in downstream applications that NVD matched by keyword search.

Examples that need to be discounted before any hacker reasoning:

- **sqlite (27 events claimed):** Of these, ~3 are actual SQLite library bugs (CVE-2025-6965 sqlite3KeyInfo integer overflow, CVE-2025-7458 sqlite3KeyInfoFromExprList integer overflow, CVE-2025-54379 LF Edge eKuiper [downstream]). The other ~24 are CVEs in other applications that happen to use SQLite — FUXA, METIS WIC, n8n, langchain-ai, MyTube, SciTokens, PraisonAI, Cockpit, Kysely, SiYuan, etc. **Tier D as a cluster — not bugs in our SQLite.**
- **systemd (15 events claimed):** Of these, 6-7 are Linux kernel CVEs (drm/i915, wifi/brcmfmac, fs/writeback, kernfs, drm/xe) keyword-matched via systemd. The rest include OpenClaw videogame, BlueChi orchestrator, snapd (Ubuntu/Canonical, not Amazon Linux 2023), GNU inetutils telnetd, Himmelblau (Azure Entra), Incus container manager. **Genuine systemd bugs in this list: 0.**
- **zlib (8 events claimed):** ~3 actual zlib lib bugs (CVE-2025-4638 inftrees.c, CVE-2025-14847 length mismatch, CVE-2026-22184 inflateBack global buffer overflow). The others are Perl Compress::Raw::Zlib, undici WebSocket, Open Babel, Unfurl — downstream apps.

This is exactly the "NVD keyword noise" the limitations section already calls out. The hacker reasoning below is on the cleaned set — actual OS-component CVEs only.

## Cleaned event roster (≈18 actual OS-component CVEs)

| Component | Real CVEs (12mo) | Notes |
|---|---|---|
| libxml2 | 4 | use-after-free, NULL deref, OOB read on XML parsing |
| libarchive | 4 | RAR5 infinite loop, OOB read, integer overflow on archive parsing |
| sqlite | 3 | integer overflows in query optimizer; reachable via SQL input |
| zlib | 3 | decompression buffer issues |
| nghttp2 | 2 | DoS in HTTP/2 frame handling |
| expat | 2 | memory exhaustion + Perl XML::Parser overflow |
| krb5 | 1 | integer overflow in incremental propagation |
| pcre2 | 1 | OOB read/write in JIT compiler |
| python39 | 1 | CPython tarfile module defect |
| openjdk (OpenJ9) | 1 | stack overflow in native file processing |
| rpm | 1 | Yggdrasil broker (RHEL only — questionable for AL2023) |

The remaining ~50 events are NVD keyword noise.

## Tier rankings

### S — unconditional one-shot RCE from internet

**0 events.** None of these OS-layer CVEs are reachable as a one-shot from internet on a Spring stack. The Spring app handles all ingress; OS libraries are post-compromise surface.

### A — strong primitive at default config, internet-edge reach OR clean post-compromise privesc

**0 events on the cleaned set, 1-2 in the "kernel via systemd keyword" cluster if those count.**

Looking at the kernel CVEs that NVD keyword-matched into systemd:
- **drm/i915 use-after-free** (CVE-2023-53112), **kernfs UAF** (CVE-2025-39881), **fs/writeback UAF** (CVE-2025-39866) — these are kernel use-after-frees that, if the container shares the host kernel (and most do), could be A-tier post-exploitation privesc paths. The standard caveats apply: kernel UAF reliability is highly version-specific; reaching them requires holding code execution in the container already; container runtimes (containerd/runc) sometimes block the syscalls needed.

**Tier A (with caveats) for 2-3 of the kernel cluster** — but only as post-compromise privesc, not as initial-access primitives. The hacker's app-layer S+A discriminator is doing all the initial-access work; this layer's value is "what does the attacker get *after* the app-layer breach succeeds."

### B — opportunistic, narrow precondition

- **CVE-2025-49794 libxml2 use-after-free** (CWE-825 + CVSS 9.1) — UAF when parsing schematron/XPath. Reachable IF the Spring app passes attacker XML through libxml2 (rare; Java apps usually use built-in javax.xml, not libxml2 native). **B for apps that use the JVM SAX adapter that wraps libxml2; D otherwise.**
- **CVE-2025-49796 libxml2 OOB read** (sch:name CRITICAL 9.1) — same reachability gate. **B-conditional.**
- **CVE-2026-5121 libarchive integer overflow on 32-bit** — heap corruption on RAR5 parsing. Reachable IF app processes attacker-supplied archives via shell-out or native binding. CVSS 9.8 but realistic primitive only on 32-bit deployments (rare in 2026). **B-conditional, leaning C.**
- **CVE-2025-58050 pcre2 JIT OOB write** — heap corruption in JIT compiler. Reachable IF app uses pcre2-jit-bound regex on attacker-controlled patterns (very rare in Java; standard java.util.regex is unaffected). **B for apps with native pcre2 bindings; D otherwise.**
- **CVE-2025-4447 OpenJ9 stack overflow** — native stack overflow when JDK processes specific files. Reachable post-exploitation as a different-failure-mode primitive. **B post-compromise.**
- **CVE-2025-4638 zlib inftrees.c CWE-119** — buffer issue in decompression. Reachable through HTTP gzip if attacker controls content-encoding chain. **B for apps that decompress attacker bodies; C for typical Spring with standard Tomcat compression.**

### C — defense-in-depth, MITM-needed, requires unusual chain

- **CVE-2025-66568 ruby-saml signature** (CWE-347, CVSS 9.1) — keyword-matched via libxml2 but it's actually a ruby-saml SAML auth bypass. **C** — only relevant if the Spring app uses ruby-saml (it doesn't; it's a Spring-Security/Java SAML stack).
- **CVE-2025-30194 nghttp2 DoH** — DoS in DNSdist's DoH provider. Spring app isn't a DNS server. **C.**
- **CVE-2026-27135 nghttp2 reachable assertion** — DoS via crafted HTTP/2 frame on nghttp2 servers. Spring uses Tomcat HTTP/2, not nghttp2. **C/D for this stack.**
- **CVE-2025-24528 krb5 integer overflow in iprop** — reachable on Kerberos KDC servers, not on Kerberos clients. Spring app is a client at most. **C.**
- **CVE-2026-4111, -4424 libarchive on RAR/heap** — same reachability story as -5121 above. **C absent app-level archive processing.**
- **CVE-2025-14847 zlib mismatched length** — exploited via MongoDB wire protocol per the External Validation section above. **C for this Spring stack** (not via Tomcat HTTP); it does have a Metasploit module but in a deployment context that doesn't apply.
- **CVE-2026-3888 snapd LPE** — Ubuntu/Canonical snap; not in Amazon Linux 2023. **D for this manifest** (NVD scope error).

### D — DoS only, info leak, weak crypto, NVD keyword noise

- All 50+ NVD keyword-noise CVEs (SQLite-using applications, systemd-keyword kernel CVEs unrelated to systemd-the-init-system, downstream zlib consumers, etc.) → **D.**
- Genuine OS-layer DoS: nghttp2 DoH DoS, expat memory exhaustion, libarchive infinite loop, python39 tarfile defect → **D.**
- CVE-2026-2515 BlueChi PHYSICAL attack vector → **D.**
- CVE-2026-32606 IncusOS PHYSICAL → **D.**

## Summary table

| Tier | Count (after NVD-noise clean-up) | Notes |
|---|---|---|
| **S** | 0 | No internet-direct primitive on OS-layer libs |
| **A** | 0–3 | Conditional on counting kernel UAF cluster as post-compromise privesc |
| **B** | 2–6 | Mostly libxml2 / libarchive / pcre2 / zlib UAFs and OOB writes — all gated on whether the Spring app uses native binding paths to those libs (mostly it doesn't) |
| **C** | 6–8 | Real bugs but reachability gates fail in this deployment shape |
| **D** | 50+ | Mix of genuine DoS and NVD keyword noise from downstream apps |

## Cross-layer headline

**This finding reproduces the published periodicity claim from a different angle.** The published periodicity page reports zero OS-layer NP+DI events in 12 months. The hacker discriminator agrees: **zero S-tier and zero unconditional A-tier events on the OS layer**. The analysis is consistent across the two filters because the structural fact is the same — the Spring app is the trust boundary, and the OS-layer libraries underneath it are reachable only after that boundary is crossed.

Where the hacker view adds something the published periodicity doesn't: **most of the 69 "OS layer" CVEs are NVD keyword noise**, not actual bugs in the OS components. The published periodicity says "21 LOCAL CVEs accumulate" — the hacker pass shows that of those 21, roughly half are keyword-matched kernel CVEs (systemd-the-keyword catching kernel-the-CVE) and the other half are unrelated apps that happen to share a name with an OS component. The actual count of LPE-relevant bugs in components actually present in Amazon Linux 2023 is closer to 5-10, not 21. **The structural finding holds — monthly container refresh is good policy regardless** — but the specific "21 privesc CVEs" number overstates the genuine post-compromise risk surface.

## Operational implication for the integrated page

Two things this round confirms or refines:

1. **Hacker S+A on OS layer = 0 (or at most 2-3 conditional-A kernel UAFs).** This matches the NP+DI = 0 finding. The OS layer does not produce emergency rebuild triggers under either filter — the *app* layer is what drives the cadence. The two-layer model (app drives IF, OS drives HOW BAD) survives the hacker pass.

2. **The "21 LOCAL privesc CVEs" worst-case number is inflated by NVD keyword noise.** The blast-radius argument for monthly container refresh is still right (more privesc surface = bigger attacker payoff after breach), but the *specific number* depends on how aggressive your CVE-to-component matching is. The published periodicity already flagged this in its "additional caveat" paragraph; this round quantifies it: roughly half the LOCAL count is noise, about 5-10 are genuine LPE-relevant bugs in components actually present in Amazon Linux 2023.

The three-tier patching model (Tier 1 emergency for app-layer NP+DI, Tier 2 monthly for OS, Tier 3 normal update process for everything else) is unchanged by this round. What changes is the rationale for Tier 2: it's about reducing *real* privesc surface (5-10 LPE bugs/year), not the inflated NVD count.
