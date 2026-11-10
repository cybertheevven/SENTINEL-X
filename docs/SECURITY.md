# Security & Privacy
- Use only on evidence you are authorized to analyze.
- Originals are read, never modified; working copies are chmod read-only; hashes re-verified before every analysis.
- No remote exploitation, credential harvesting, persistence or evasion code exists in this project.
- AI is local (Ollama) and receives findings only. Cloud AI is NOT implemented; when added it must require explicit consent and redaction.
- Reports may contain IPs and URLs from the evidence: handle them as confidential.
- Known limitation: the custody log is append-only by convention, not cryptographically tamper-proof (planned: hash-chained log).
