package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Applies per-IP rate limiting to a controller endpoint.
 *
 * <p>Enforced by {@link com.dev.app.config.RateLimitInterceptor}.
 * Returns HTTP 429 Too Many Requests when the limit is exceeded.</p>
 *
 * <pre>{@code
 * @RateLimit(requests = 5, windowSeconds = 60)
 * @PostMapping("/login")
 * public ResponseEntity<?> login(...) { ... }
 * }</pre>
 *
 * @param requests      max number of requests allowed per window (default 10)
 * @param windowSeconds sliding window duration in seconds (default 60)
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {
    int requests() default 10;
    int windowSeconds() default 60;
}
