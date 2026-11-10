# Architecture (v0.1.0)
```
CLI (cli/main.py)
 -> Case (core/case.py) + custody.log
 -> EvidenceStore (evidence/collector.py): copy, SHA-256, manifest, verify
 -> pipeline (core/pipeline.py): verify -> parsers/web.py -> analyzers/detection.py
      -> investigation/initial_access.py -> timeline/builder.py -> analyzers/ioc.py -> analysis.json
 -> ai/ollama.py (optional): findings-only prompt, citation validation -> ai_investigation.json
 -> reporting/json_report.py, reporting/pdf_report.py
```
Extension points: add parsers under `parsers/` returning `LogEvent`s; add rules in `analyzers/`; AI providers behind `ai/`.
