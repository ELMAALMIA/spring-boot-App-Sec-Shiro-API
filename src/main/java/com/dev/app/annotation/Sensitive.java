package com.dev.app.annotation;

import java.lang.annotation.*;

/**
 * Marks a field or parameter as sensitive — its value must never appear in logs.
 *
 * <p>Acts as documentation for developers and is processed at the logging layer by
 * {@link com.dev.app.config.SensitiveMaskingConverter}, which replaces known sensitive
 * field patterns (e.g. {@code password=...}, {@code "token":"..."}) with {@code ***}
 * in all log messages.</p>
 *
 * <pre>{@code
 * public record LoginRequest(
 *     String username,
 *
 *     @Sensitive
 *     String password
 * ) {}
 * }</pre>
 */
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Sensitive {
}
