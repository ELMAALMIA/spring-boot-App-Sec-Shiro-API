package com.dev.app.config;

import com.dev.app.annotation.IsAdmin;
import com.dev.app.annotation.IsUser;
import com.dev.app.annotation.PermissionCheck;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.exception.UnauthorizedAccessException;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * AOP security aspect that enforces role and permission annotations.
 *
 * <p>Handles three annotations via {@link Around} advice:</p>
 * <ul>
 *   <li>{@link IsAdmin}       — requires ADMIN role</li>
 *   <li>{@link IsUser}        — requires USER role</li>
 *   <li>{@link PermissionCheck} — requires a specific Shiro permission string</li>
 * </ul>
 *
 * <p>All checks verify authentication first, then role/permission.
 * Relies on Shiro's Subject being bound to ThreadContext by {@link ShiroSessionFilter}.</p>
 */
@Aspect
@Component
public class SecurityAspect {

    private static final Logger log = LoggerFactory.getLogger(SecurityAspect.class);

    // -----------------------------------------------------------------------
    // @IsAdmin
    // -----------------------------------------------------------------------

    @Around("@annotation(isAdmin)")
    public Object checkAdminRole(ProceedingJoinPoint pjp, IsAdmin isAdmin) throws Throwable {
        Subject subject = requireAuthenticated();
        if (!subject.hasRole("ADMIN")) {
            log.warn("@IsAdmin check failed — user='{}' lacks ADMIN role", subject.getPrincipal());
            throw new UnauthorizedAccessException("Access denied — ADMIN role required");
        }
        return pjp.proceed();
    }


    // @IsUser


    @Around("@annotation(isUser)")
    public Object checkUserRole(ProceedingJoinPoint pjp, IsUser isUser) throws Throwable {
        Subject subject = requireAuthenticated();
        if (!subject.hasRole("USER")) {
            log.warn("@IsUser check failed — user='{}' lacks USER role", subject.getPrincipal());
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


    private Subject requireAuthenticated() {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            throw new AuthenticationFailedException("Not authenticated");
        }
        return subject;
    }
}
