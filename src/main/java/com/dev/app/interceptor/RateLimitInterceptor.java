package com.dev.app.interceptor;

import com.dev.app.annotation.RateLimit;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-IP rate limiting interceptor for endpoints annotated with {@link RateLimit}.
 *
 * <h3>Thread-safety</h3>
 * The decision (allowed / rate-limited) is made <em>entirely inside</em>
 * {@link ConcurrentHashMap#compute}, which is atomic per key. A {@code boolean[]}
 * capture is used because the check must be available outside the lambda, but the
 * value is set exclusively inside the atomic block — no TOCTOU window.
 *
 * <h3>Memory</h3>
 * Entries expire lazily: a key is reset when its window has elapsed.
 * For high-traffic production systems replace with a Redis-backed implementation.
 *
 * <p>Registered in {@code WebMvcConfig}.</p>
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    private final ObjectMapper objectMapper;
    private final ConcurrentHashMap<String, RateLimitEntry> store = new ConcurrentHashMap<>();

    public RateLimitInterceptor(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws IOException {

        if (!(handler instanceof HandlerMethod hm)) return true;

        RateLimit rl = hm.getMethodAnnotation(RateLimit.class);
        if (rl == null) return true;

        String key = request.getRemoteAddr() + ":" + request.getRequestURI();
        long now = System.currentTimeMillis();
        long windowMillis = (long) rl.windowSeconds() * 1000;

        /*
         * The exceeded flag is set INSIDE compute(), which ConcurrentHashMap guarantees
         * runs atomically per key. No other thread can interleave between the increment
         * and the threshold check — eliminating the TOCTOU race condition.
         */
        boolean[] exceeded = {false};

        store.compute(key, (k, v) -> {
            if (v == null || now - v.windowStart >= windowMillis) {
                return new RateLimitEntry(now, 1);
            }
            v.count++;
            if (v.count > rl.requests()) {
                exceeded[0] = true;
            }
            return v;
        });

        if (exceeded[0]) {
            log.warn("Rate limit exceeded: ip={} uri={}", request.getRemoteAddr(), request.getRequestURI());
            sendTooManyRequests(response, rl);
            return false;
        }

        return true;
    }

    private void sendTooManyRequests(HttpServletResponse response, RateLimit rl) throws IOException {
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(Map.of(
                "status", 429,
                "error", "Too Many Requests",
                "message", String.format("Rate limit exceeded — max %d requests per %d seconds",
                        rl.requests(), rl.windowSeconds())
        )));
    }

    static class RateLimitEntry {
        long windowStart;
        int count;

        RateLimitEntry(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }
}
