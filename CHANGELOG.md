# Changelog

## 0.2.0
- SSH auth.log / secure parser (classic + ISO syslog) with automatic format detection
- SSH detections: brute force, user enumeration, successful login after failures (Observed), root login
- Web <-> SSH correlation (Inferred), initial-access assessment now includes confirmed access events
- Attack-path graph, remediation recommendations, self-contained HTML dashboard, upgraded PDF (logo, KPIs, graph)
- `sentinel-x demo`, `report --format html|all`, `analyze --year`
- GitHub-ready: CI workflow, install/publish scripts, CONTRIBUTING, SECURITY, issue/PR templates
- 51 tests

## 0.1.0 - MVP
- Case management, evidence collector, Apache/Nginx parser, detection rules, timeline, IOC, optional Ollama, JSON/PDF
