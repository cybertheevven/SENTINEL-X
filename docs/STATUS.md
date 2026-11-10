# Implementation status - v0.2.0

| Spec module | Status | Notes |
|---|---|---|
| 01 Evidence Collector | **Implemented + tested** | read-only copy, SHA-256, EV-IDs, manifest, custody log (append-only by convention) |
| 02 Log Analyzer | **Implemented + tested** (Apache/Nginx) | SQLi, traversal, web shell, sensitive paths, scanner UA, brute force, 404 enumeration |
| 03 Initial Access | **Implemented + tested** | hypothesis or `Undetermined`; confirmed SSH logins listed separately |
| 04 Attack Timeline | **Implemented + tested** | phases only if supported; attack-path graph (SVG/PDF) |
| 05 Infrastructure analysis | Partial | IP/UA/URL extraction; DNS/ASN/geo/VPN/Tor not implemented |
| 06 Authentication | **Implemented + tested** (SSH) | brute force, enumeration, success after failures, root login. Not yet: new accounts, odd login hours, Windows events |
| 07 Post-Intrusion Forensics | Roadmap | file integrity, authorized_keys, cron, services |
| 08 Data Access/Exfiltration | Roadmap | |
| 09 IOC Intelligence | Partial | local IOC list; no external enrichment |
| 10 AI Assistant | **Implemented (Ollama), unit-tested with mocks** | NOT tested against a live model |
| Reports | **Implemented + tested** | PDF, HTML dashboard, JSON (English only) |
| Remediation advice | **Implemented + tested** | generic, derived from finding types |
| CLI + demo | **Implemented + tested** | |
| CI (GitHub Actions) | Written, runs on first push | not yet executed |
| Docker | Files written, **not built** | |
| SQLite / FastAPI / Dashboard server | Roadmap | HTML report is static |
| Cloud AI / OpenAI-compatible | Roadmap | deliberately absent |
| PDF User Guide | Roadmap | Markdown docs only |

## Verified in the build environment
51 tests pass; demo run produces PDF/HTML/JSON; HTML and PDF visually inspected; attacker-controlled log content is escaped.
Not verified: live Ollama, Docker, GitHub Actions, real-world logs, performance on large files.
