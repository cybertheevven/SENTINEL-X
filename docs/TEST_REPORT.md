# Test report - v0.2.0
`python3 -m unittest discover -s tests -t . -p "test_*.py"` -> **51 passed, 0 failed**.

Areas: web parser; SSH parser (classic/ISO/IPv6/year rollover/format sniffing); detection rules incl. thresholds and
false-positive guards (benign traffic, legit SSH login, success-before-failures); correlation; initial access;
evidence hashing/tamper detection; AI fallback + citation validation (mocked); reports (JSON/PDF/HTML), attack-path graph
(SVG well-formed, PDF drawing), remediation ordering; **HTML/PDF escaping of malicious log content**; CLI end-to-end and `demo`.
Not covered: live Ollama, Docker, large inputs, real logs.
