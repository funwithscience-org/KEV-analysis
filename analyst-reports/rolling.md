# KEV Analyst — Rolling Observations

A living log of cross-run trends, written by the daily analyst agent. Newest entries on top. Each dated section is 2–3 observations distilled from that day's full report (see sibling dated .md files).

## 2026-04-17: Ten days post-Mythos-launch, KEV looks completely normal
- 14 April KEV adds through day 17 pace with the 2026 monthly average (~24/mo) and skew enterprise-edge (Fortinet, Ivanti, SharePoint, Exchange, ActiveMQ, NetScaler). No Glasswing-target products (Firefox/wolfSSL/NGINX/FreeBSD/OpenSSL) appear in April KEV so far — consistent with the 4–8 week NVD-publish-latency argument, but also consistent with "Glasswing exploitation-relevant signal is smaller than expected." We cannot distinguish those hypotheses until ~mid-May.
- CVE-2026-32201 (SharePoint actively exploited 0-day, CVSS **6.5**) is the cleanest CVSS-doesn't-predict-exploitation data point of the month. KEV added day-of disclosure. HTTP-parsing-adjacent thesis continues to hold at ~7 of 14 April entries (50%).
- CVE-2026-5588 (Bouncy Castle, published 2026-04-15, credited to Nicholas Carlini using Claude) is the first publicly visible "Claude-assisted but not Glasswing" CVE in the cryptographic-library space. Not KEV-listed. Early signal worth watching for clustering.

<!-- Future entries prepend above this line -->
