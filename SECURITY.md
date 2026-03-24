# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Active |
| older branches | ❌ No longer maintained |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, report it privately so it can be fixed before public disclosure:

1. Go to the **[Security tab](https://github.com/ELMAALMIA/spring-boot-App-Sec-Shiro-API/security/advisories/new)** of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details: affected component, steps to reproduce, impact, and suggested fix (if any)

You will receive a response within **72 hours**. Once the issue is confirmed and fixed, a public advisory will be published crediting the reporter (unless you prefer to remain anonymous).

## Scope

Vulnerabilities in scope:
- Authentication bypass or privilege escalation
- Session fixation or session hijacking
- Account lockout bypass
- Sensitive data exposure (logs, error messages, API responses)
- Injection vulnerabilities (SQL, command, JNDI)
- Insecure deserialization

Out of scope:
- Vulnerabilities in third-party dependencies (report directly to the dependency maintainer)
- Issues only reproducible on unsupported configurations
- Theoretical risks with no practical exploit path

## Security Design

This project documents its security architecture in [`README.md`](README.md). Key protections include SHA-512 password hashing, session fixation prevention, account lockout, rate limiting, audit logging, and sensitive data masking. See the README for the full threat model.
