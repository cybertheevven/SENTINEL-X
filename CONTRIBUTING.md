# Contributing
1. Fork, create a branch, make focused changes.
2. Add tests (unit tests use synthetic data only - documentation IP ranges 198.51.100.0/24, 203.0.113.0/24).
3. Run `python -m unittest discover -s tests -t . -p "test_*.py"`.
4. Rules: defensive features only; never modify original evidence; every conclusion must be traceable to evidence (ID + line); keep Observed/Inferred/Unknown and severity vs confidence separate.
Never commit real logs, credentials or API keys.
