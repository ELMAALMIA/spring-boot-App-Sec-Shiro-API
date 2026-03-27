---
name: Bug Report
about: Something is broken or behaving incorrectly
title: "[BUG] "
labels: bug
assignees: ELMAALMIA
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Start the app with `docker compose up` or `./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`
2. Call endpoint `...`
3. See error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include the full error message or log output.

```
paste logs here (remove any sensitive data)
```

## Environment

| Property | Value |
|---|---|
| JDK version | e.g. 17.0.10 |
| Spring Boot | 3.5.11 |
| Apache Shiro | 2.1.0 |
| OS | e.g. Ubuntu 22.04 / Windows 11 |
| Docker version | e.g. 27.x (if using Docker) |
| Profile active | `dev` / `prod` |

## Additional Context

Any other context, screenshots, or related issues.
