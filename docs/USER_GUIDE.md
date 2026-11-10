# User Guide (v0.1.0)

| Command | Purpose |
|---|---|
| `case create --name N` / `case list` | Create/list investigation cases |
| `evidence add --case N --path P` | Copy file/dir (recursive) as read-only evidence, hash it, assign EV-IDs; exact duplicates are skipped |
| `evidence list|verify --case N` | List evidence / re-check SHA-256 (exit 1 on mismatch) |
| `analyze --case N [--bruteforce-threshold X] [--enum-404-threshold Y]` | Verify integrity, parse, detect, assess initial access, build timeline + IOCs |
| `ai investigate --case N [--host H --model M]` | Optional Ollama summary (exit 3 if unavailable) |
| `report generate --case N --format pdf|json|both [--output PATH]` | Create reports in `<case>/reports/` |

Analysis refuses to run if any working copy no longer matches its SHA-256 (exit 2).
Case files: `case.json`, `manifest.json`, `analysis.json`, `ai_investigation.json`, `custody.log` (append-only action log), `reports/`.

## Reading findings
- **Classification**: Observed = in the evidence; Inferred = derived from indicators; Unknown = not provable.
- **A request that looks malicious is Observed; whether it worked is not** - check app/auth/DB logs.
- Thresholds (defaults): 5 failed logins/300 s per IP; 15 x 404/60 s per IP.

## v0.2.0 additions
| Command | Purpose |
|---|---|
| `demo [--name N] [--output-dir D]` | Full demo on synthetic logs; reports in `D/reports` |
| `report generate --format pdf\|json\|html\|both\|all` | `all` (default) = pdf+json+html; `both` = pdf+json |
| `analyze --year YYYY` | Year for syslog timestamps without a year (default: file mtime year; times treated as UTC) |

Evidence format is detected automatically (`web`, `auth`); unrecognized files are listed as unsupported, never silently ignored.
