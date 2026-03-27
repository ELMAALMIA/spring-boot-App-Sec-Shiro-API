# Contributing to spring-boot-app-sec-shiro

Thank you for taking the time to contribute! This project is a reference implementation — contributions that improve correctness, security, clarity, or test coverage are especially welcome.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Branch & Commit Conventions](#branch--commit-conventions)
- [Pull Request Process](#pull-request-process)
- [Good First Issues](#good-first-issues)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

---

## How to Contribute

### Bug reports
Open an issue using the **Bug Report** template. Include:
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (mask any sensitive data)
- Environment (JDK version, OS, Docker version if applicable)

### Feature requests
Open an issue using the **Feature Request** template. Explain the use case before proposing an implementation.

### Code contributions
1. Check [open issues](https://github.com/ELMAALMIA/spring-boot-App-Sec-Shiro-API/issues) — comment on one to claim it before starting
2. Fork the repository
3. Create a branch from `main` (see naming conventions below)
4. Write code + tests
5. Open a pull request against `main`

---

## Development Setup

**Requirements:** JDK 17+, Maven 3.9+, Docker (optional)

```bash
# Clone your fork
git clone https://github.com/<your-username>/spring-boot-App-Sec-Shiro-API.git
cd spring-boot-App-Sec-Shiro-API

# Run tests
./mvnw test

# Run locally (dev profile — seeds test users + enables Swagger)
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev

# Run via Docker
docker compose up --build
```

Swagger UI available at `http://localhost:8080/swagger-ui/index.html`

---

## Branch & Commit Conventions

**Branch names:**
```
feature/<short-description>     # new features
fix/<short-description>         # bug fixes
docs/<short-description>        # documentation only
chore/<short-description>       # tooling, CI, dependencies
```

**Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat: add Redis-backed rate limiter
fix: prevent session creation after response commit
docs: add sequence diagram for account lockout flow
chore: upgrade Shiro to 2.2.0
test: add unit tests for SensitiveMaskingConverter
```

---

## Pull Request Process

1. All tests must pass (`./mvnw test`)
2. No new compiler warnings
3. New behavior must be covered by tests
4. Update the README if you add or change a public feature
5. Keep PRs focused — one concern per PR
6. Fill in the PR template completely

A maintainer will review within a few days. Be responsive to review feedback.

---

## Good First Issues

Look for issues tagged [`good first issue`](https://github.com/ELMAALMIA/spring-boot-App-Sec-Shiro-API/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). These are well-scoped, low-risk tasks suitable for first-time contributors.

Current candidates:
- Add unit tests for `SensitiveMaskingConverter` regex edge cases
- Add parameterized validation tests for `LoginRequest`
- Add CSRF token filter
- Document Redis rate limiter as an alternative to in-memory

---

## Reporting Security Vulnerabilities

**Do not open a public issue.** See [`SECURITY.md`](SECURITY.md) for the responsible disclosure process.
