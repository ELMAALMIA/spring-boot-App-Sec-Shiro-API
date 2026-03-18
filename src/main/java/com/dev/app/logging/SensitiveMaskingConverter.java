package com.dev.app.logging;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.regex.Pattern;

/**
 * Logback {@link MessageConverter} that masks sensitive values in log messages.
 *
 * <p>Activated via {@code logback-spring.xml} using the conversion word {@code maskedMsg}.
 * All log output uses {@code %maskedMsg} instead of {@code %msg}, so sensitive data
 * is never written to any appender.</p>
 *
 * <p>Masked patterns (case-insensitive):</p>
 * <ul>
 *   <li>JSON field:  {@code "password":"secretValue"}  → {@code "password":"***"}</li>
 *   <li>Query param: {@code password=secretValue}      → {@code password=***}</li>
 *   <li>Covers: password, passwd, secret, token, authorization, apikey, api_key</li>
 * </ul>
 *
 * <p>Fields annotated with {@link com.dev.app.annotation.Sensitive} are the primary
 * source of sensitive data; this converter acts as the enforcement layer.</p>
 */
public class SensitiveMaskingConverter extends MessageConverter {

    private static final Pattern[] PATTERNS = {
        // JSON-style:  "password" : "someValue"
        Pattern.compile(
            "(\"(?:password|passwd|secret|token|authorization|apikey|api_key)\"\\s*:\\s*\")([^\"]*)(\")",
            Pattern.CASE_INSENSITIVE
        ),
        // Key=value style: password=someValue (ends at space, comma, &, })
        Pattern.compile(
            "((?:password|passwd|secret|token|authorization|apikey|api_key)\\s*=\\s*)([^\\s,&}]+)",
            Pattern.CASE_INSENSITIVE
        ),
    };

    @Override
    public String convert(ILoggingEvent event) {
        String message = event.getFormattedMessage();
        if (message == null) return "";

        for (Pattern pattern : PATTERNS) {
            message = pattern.matcher(message).replaceAll(mr -> {
                // Group 1 = prefix, group 2 = secret value, group 3 = suffix (JSON only)
                String prefix = mr.group(1);
                String suffix = mr.groupCount() >= 3 ? mr.group(3) : "";
                return prefix + "***" + suffix;
            });
        }

        return message;
    }
}
