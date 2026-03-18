package com.dev.app.security.aspect;

import com.dev.app.annotation.IsAdmin;
import com.dev.app.annotation.IsUser;
import com.dev.app.annotation.PermissionCheck;
import com.dev.app.enums.RoleName;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.exception.UnauthorizedAccessException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * AOP security aspect that enforces role and permission annotations.
 *
 * <p>Handles three annotations via {@link Around} advice:</p>
 * <ul>
 *   <li>{@link IsAdmin}        — requires {@link RoleName#ADMIN} role</li>
 *   <li>{@link IsUser}         — requires {@link RoleName#USER} role</li>
 *   <li>{@link PermissionCheck} — requires a specific Shiro wildcard permission</li>
 * </ul>
 *
 * <p>Role names come exclusively from {@link RoleName#name()} — no raw string literals,
 * so a typo in role names is caught at compile time.</p>
 *
 * <p>{@code @Order(1)} ensures this aspect runs first (highest precedence) before any
 * other aspects on the same join point, guaranteeing security checks gate all business
 * logic regardless of future aspect additions.</p>
 *
 * <p>Relies on Shiro's Subject being bound to ThreadContext by
 * {@link com.dev.app.filter.ShiroSessionFilter} before the request reaches the controller layer.</p>
 */
@Aspect
@Component
@Order(1)
public class SecurityAspect {

    private static final Logger log = LoggerFactory.getLogger(SecurityAspect.class);

    // -----------------------------------------------------------------------
    // @IsAdmin
    // -----------------------------------------------------------------------

    @Around("@annotation(isAdmin)")
    public Object checkAdminRole(ProceedingJoinPoint pjp, IsAdmin isAdmin) throws Throwable {
        Subject subject = requireAuthenticated();
        if (!subject.hasRole(RoleName.ADMIN.name())) {
            log.warn("@IsAdmin check failed — user='{}' lacks {} role",
                    subject.getPrincipal(), RoleName.ADMIN);
            throw new UnauthorizedAccessException("Access denied — ADMIN role required");
        }
        return pjp.proceed();
    }

    // -----------------------------------------------------------------------
    // @IsUser
    // -----------------------------------------------------------------------

    @Around("@annotation(isUser)")
    public Object checkUserRole(ProceedingJoinPoint pjp, IsUser isUser) throws Throwable {
        Subject subject = requireAuthenticated();
        if (!subject.hasRole(RoleName.USER.name())) {
            log.warn("@IsUser check failed — user='{}' lacks {} role",
                    subject.getPrincipal(), RoleName.USER);
            throw new UnauthorizedAccessException("Access denied — USER role required");
        }
        return pjp.proceed();
    }

    // -----------------------------------------------------------------------
    // @PermissionCheck
    // -----------------------------------------------------------------------

    @Around("@annotation(permissionCheck)")
    public Object checkPermission(ProceedingJoinPoint pjp, PermissionCheck permissionCheck) throws Throwable {
        Subject subject = requireAuthenticated();
        String permission = permissionCheck.value();
        if (!subject.isPermitted(permission)) {
            log.warn("@PermissionCheck failed — user='{}' lacks permission '{}'",
                    subject.getPrincipal(), permission);
            throw new UnauthorizedAccessException("Access denied — missing permission: " + permission);
        }
        return pjp.proceed();
    }

    // -----------------------------------------------------------------------
    // Shared helper
    // -----------------------------------------------------------------------

    private Subject requireAuthenticated() {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            throw new AuthenticationFailedException("Not authenticated");
        }
        return subject;
    }
}
