# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-24

### Added

**Security features**
- Session fixation prevention: session ID rotated on every login via `ContentCachingResponseWrapper` + `HttpSession.invalidate()` + `getSession(true)`
- Account lockout: atomic `@Modifying @Query` increments `failed_attempts`; account locked for 15 min after 5 failures
- Rate limiting: `@RateLimit` annotation enforced by `RateLimitInterceptor` using TOCTOU-safe `ConcurrentHashMap.compute()`
- Security response headers filter: `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, `Referrer-Policy`, full CSP
- Persistent audit log: `AuditEvent` entity records LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_BLOCKED_LOCKED, LOGOUT, ACCOUNT_UNLOCKED with IP address
- Sensitive data masking: Logback `SensitiveMaskingConverter` redacts password/token patterns from log output
- Timing equalization: dummy hash computed on unknown-user paths to prevent username enumeration via timing

**Authorization**
- AOP-based access control via `@IsAdmin`, `@IsUser`, `@PermissionCheck` annotations (processed by `SecurityAspect`)
- `@CurrentUser` annotation injected via `CurrentUserArgumentResolver` from Shiro ThreadContext
- `RoleName` enum used throughout — no raw `"ADMIN"`/`"USER"` strings

**Infrastructure**
- Jakarta-native `ShiroSessionFilter` replacing `shiro-web` (javax.servlet incompatible with Spring Boot 3)
- `MemoryConstrainedCacheManager` wired to `DatabaseRealm` eliminating N+1 authorization queries per request
- Constructor injection throughout — no `@Autowired` field injection
- `AppException` base class unifying all domain exceptions

**Developer experience**
- Environment profiles: `dev` (SQL logging, Swagger, H2 console, seeded users) / `prod` (hardened defaults)
- `DataLoader` gated behind `@ConditionalOnProperty(app.seed-test-users=true)`
- Multi-stage Dockerfile with non-root runtime user
- `docker-compose.yml` for instant `docker compose up` demo
- GitHub Actions CI on every push / pull request
- OpenAPI / Swagger UI with full endpoint documentation
- Mermaid architecture diagrams in README (request pipeline, login sequence, lockout state machine, ER diagram)

**Testing**
- 27 tests across unit (`AuthServiceImplTest`, `ShiroSessionFilterTest`) and integration (`AuthIntegrationTest`)

### Security notes

- Password hashing: SHA-512, 50 000 iterations, per-user salt (Shiro `DefaultPasswordService`)
- `SameSite=Strict`, `HttpOnly=true` on session cookies
- H2 console disabled by default; never reachable in prod profile
- Swagger disabled by default; enabled only in dev profile

---

## [Unreleased]

- CSRF filter
- Redis-backed distributed rate limiter
- PostgreSQL + Flyway migration branch
- `SensitiveMaskingConverter` unit tests
