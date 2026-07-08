"""ScamVapt — a confirmation-first vulnerability assessment framework.

Consumes the validated attack surface produced by ScamRecon (`recon.py`) and
runs targeted, best-in-class exploitation tools (sqlmap, ghauri, dalfox, commix,
nuclei-dast, crlfuzz, …) to confirm ONLY critical/high vulnerabilities.

Design principle: **zero false positives.** A finding is reported only when a
tool actually *proves* it — sqlmap confirms an injection, dalfox verifies XSS
execution, an LFI payload returns a real `/etc/passwd` signature, commix lands a
command. Everything unproven is quarantined as "needs manual review," never
mixed into the confirmed findings.
"""

__version__ = "1.0.0"
__all__ = ["config", "vstate", "loader", "payloads", "scanners", "report", "pipeline", "installer"]
