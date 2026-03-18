package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Enforces a fine-grained Shiro permission check on a method.
 *
 * <p>Uses Shiro's wildcard permission model: {@code resource:action[:instance]}.
 * Processed by {@link com.dev.app.config.SecurityAspect} via Spring AOP.
 * Throws {@link com.dev.app.exception.UnauthorizedAccessException} if the subject
 * lacks the required permission.</p>
 *
 * <p>Built-in permission mappings (assigned in {@link com.dev.app.config.DatabaseRealm}):</p>
 * <ul>
 *   <li>ADMIN role → {@code admin:*}, {@code user:*}</li>
 *   <li>USER role  → {@code user:read}, {@code user:profile}</li>
 * </ul>
 *
 * <pre>{@code
 * @PermissionCheck("user:read")
 * @GetMapping("/users")
 * public ResponseEntity<?> listUsers() { ... }
 *
 * @PermissionCheck("admin:manage")
 * @PostMapping("/admin/users/{username}/unlock")
 * public ResponseEntity<?> unlock(...) { ... }
 * }</pre>
 *
 * @param value Shiro permission string (e.g. "user:read", "admin:manage")
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PermissionCheck {
    String value();
}
