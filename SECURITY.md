# Security and untrusted records

Receivers parse records that may be malformed or adversarial. Paths must remain
relative to an explicitly supplied root, duplicate JSON keys and non-finite
numbers are rejected, and native commands are never reconstructed from
untrusted record strings. Run external tools only through the documented
acquisition drivers in an isolated workspace.

Security reports should identify the affected parser or driver, a minimal
reproducer, and whether the issue changes a scientific judgment or only the
execution environment.
