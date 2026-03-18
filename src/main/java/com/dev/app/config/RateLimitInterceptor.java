package com.dev.app.config;

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
 * <p>Uses a sliding window per {@code IP:URI} key stored in a {@link ConcurrentHashMap}.
 * When the limit is exceeded, returns HTTP 429 with a JSON error body.</p>
 *
 * <p>Registered in {@link WebMvcConfig}.</p>
 *
 * <p><b>Note:</b> In-memory store — state is lost on restart and not shared across
 * cluster nodes. For production, replace with a Redis-backed implementation.</p>
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

        RateLimitEntry entry = store.compute(key, (k, v) -> {
            if (v == null || now - v.windowStart >= windowMillis) {
                return new RateLimitEntry(now, 1);
            }
            v.count++;
            return v;
        });

        if (entry.count > rl.requests()) {
            log.warn("Rate limit exceeded: ip={} uri={} count={}", request.getRemoteAddr(),
                    request.getRequestURI(), entry.count);
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

    /** Mutable sliding-window entry stored per IP+URI key. */
    static class RateLimitEntry {
        long windowStart;
        int count;

        RateLimitEntry(long windowStart, int count) {
            this.windowStart = windowStart;
            this.count = count;
        }
    }
}
