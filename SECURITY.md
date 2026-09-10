# Security policy

## Reporting a vulnerability in Púca

Púca is a security testing tool; please report vulnerabilities in the tool
itself **privately** via GitHub Security Advisories
(`Security` → `Report a vulnerability`), not as a public issue.

## Responsible use

Púca is for **authorized, white-hat testing only**. Every dynamic test is gated
on a `scope.yaml` that must name the exact target with explicit authorization.
Do not point Púca at systems you do not own or have written permission to test.
Follow the cloud providers' penetration-testing Rules of Engagement — never run
denial-of-service or load tests.

Engagement data, real targets, and findings must never be committed to this
public repository (`.gitignore` enforces this; keep it that way).
