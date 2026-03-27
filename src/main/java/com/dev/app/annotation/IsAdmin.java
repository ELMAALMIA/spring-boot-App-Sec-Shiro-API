package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Restricts a method or class to users with the ADMIN role.
 *
 * <p>Processed by {@link com.dev.app.config.SecurityAspect} via Spring AOP.
 * Throws {@link com.dev.app.exception.UnauthorizedAccessException} if the current
 * subject lacks the ADMIN role.</p>
 *
 * <pre>{@code
 * @IsAdmin
 * @GetMapping("/dashboard")
 * public ResponseEntity<?> dashboard() { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface IsAdmin {
}
