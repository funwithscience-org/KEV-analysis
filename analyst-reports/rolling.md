# KEV Analyst — Rolling Observations

A living log of cross-run trends, written by the daily analyst agent. Newest entries on top. Each dated section is 2–3 observations distilled from that day's full report (see sibling dated .md files).

## 2026-04-18: First mainstream-press-confirmed Mythos attribution in a Glasswing-target library
- KEV feed has not been updated in 48h (last release 2026-04-16). April KEV total holds at **14**. Today's refresh agent reports 12, disagreeing with live feed and yesterday's analyst run; treated as agent artifact.
- **Mythos signal upgraded from "inferred" to "at least one vendor-credited + press-reported."** CVE-2026-5194 (wolfSSL certificate-validation bypass, affecting ~5B devices via ECDSA/ECC, DSA, ML-DSA, Ed25519, Ed448 paths) is now widely reported as found by Nicholas Carlini at Anthropic using Claude Mythos Preview. With CVE-2026-4747 (FreeBSD NFS, autonomous Glasswing) and CVE-2026-5588 (Bouncy Castle, Carlini + Claude) that's 3 Claude-in-credit-line disclosures in 2 weeks, all in Glasswing-target / adjacent library layers. Pattern is no longer pure noise, but also not yet a step-function.
- New library-framework / HTTP-parsing data: **Thymeleaf SSTI CVE-2026-40477 & -40478 (CVSS 9.0, disclosed 2026-04-17)** — classic Spring-ecosystem template-engine restricted-object-scope bypass → unauth RCE. Natural KEV candidate within 2–4 weeks. CVE-2026-33825 (Defender BlueHammer EoP) still not in KEV 11 days post-POC; "public POC → KEV" heuristic continues to look slower than reputation suggests.

## 2026-04-17: Ten days post-Mythos-launch, KEV looks completely normal
- 14 April KEV adds through day 17 pace with the 2026 monthly average (~24/mo) and skew enterprise-edge (Fortinet, Ivanti, SharePoint, Exchange, ActiveMQ, NetScaler). No Glasswing-target products (Firefox/wolfSSL/NGINX/FreeBSD/OpenSSL) appear in April KEV so far — consistent with the 4–8 week NVD-publish-latency argument, but also consistent with "Glasswing exploitation-relevant signal is smaller than expected." We cannot distinguish those hypotheses until ~mid-May.
- CVE-2026-32201 (SharePoint actively exploited 0-day, CVSS **6.5**) is the cleanest CVSS-doesn't-predict-exploitation data point of the month. KEV added day-of disclosure. HTTP-parsing-adjacent thesis continues to hold at ~7 of 14 April entries (50%).
- CVE-2026-5588 (Bouncy Castle, published 2026-04-15, credited to Nicholas Carlini using Claude) is the first publicly visible "Claude-assisted but not Glasswing" CVE in the cryptographic-library space. Not KEV-listed. Early signal worth watching for clustering.

<!-- Future entries prepend above this line -->
