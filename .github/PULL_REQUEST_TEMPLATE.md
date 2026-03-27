## Summary

<!-- What does this PR do? 1-3 bullet points. -->

-
-

## Related Issue

<!-- Link the issue this PR resolves, e.g. "Closes #42" -->

Closes #

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring (no behavior change)
- [ ] Documentation
- [ ] CI / tooling
- [ ] Security fix

## Test Plan

- [ ] All existing tests pass (`./mvnw test`)
- [ ] New tests added for the changed behavior
- [ ] Tested manually via Swagger UI or `curl`
- [ ] Docker build passes (`docker compose up --build`)

## Security Checklist

<!-- Required for any PR touching auth, session, or access control logic -->

- [ ] No new raw role strings — `RoleName` enum used
- [ ] No `@Autowired` field injection introduced
- [ ] No sensitive data added to log statements
- [ ] No new anonymous path whitelisted without justification
- [ ] Session / ThreadContext lifecycle unchanged or improved

## Notes for Reviewer

<!-- Anything the reviewer should pay special attention to -->
