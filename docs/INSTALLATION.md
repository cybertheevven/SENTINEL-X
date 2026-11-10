# Installation
Requirements: Python 3.10+, `reportlab` (installed automatically). Optional: Ollama, Docker.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .            # installs the `sentinel-x` command
sentinel-x --version
```
Without installing: `python3 -m sentinel_x --help` from the repository root.

Validate the install: run the test suite (see README) and the Quick start with the synthetic log.
