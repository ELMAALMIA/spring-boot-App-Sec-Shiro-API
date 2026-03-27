package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Restricts a method or class to users with the USER role.
 *
 * <p>Processed by {@link com.dev.app.config.SecurityAspect} via Spring AOP.</p>
 *
 * <pre>{@code
 * @IsUser
 * @GetMapping("/profile")
 * public ResponseEntity<?> profile(@CurrentUser String username) { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface IsUser {
}
