package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Injects the currently authenticated Shiro principal (username) into a controller method parameter.
 *
 * <pre>{@code
 * @GetMapping("/me")
 * public ResponseEntity<?> me(@CurrentUser String username) { ... }
 * }</pre>
 *
 * Resolved by {@link com.dev.app.config.CurrentUserArgumentResolver}.
 * Throws {@link com.dev.app.exception.AuthenticationFailedException} if no authenticated subject exists.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentUser {
}
