package com.dev.app.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Adds standard security response headers to every HTTP response.
 *
 * <h3>Headers set</h3>
 * <ul>
 *   <li>{@code X-Content-Type-Options: nosniff} — prevents MIME-type sniffing</li>
 *   <li>{@code X-Frame-Options: DENY} — blocks clickjacking via iframes</li>
 *   <li>{@code X-XSS-Protection: 1; mode=block} — legacy XSS filter hint</li>
 *   <li>{@code Referrer-Policy: strict-origin-when-cross-origin} — limits referrer leakage</li>
 *   <li>{@code Content-Security-Policy: default-src 'self'} — restricts resource origins</li>
 *   <li>{@code Permissions-Policy} — disables camera, microphone, geolocation</li>
 *   <li>{@code Cache-Control: no-store} — prevents caching of authenticated responses</li>
 * </ul>
 *
 * <p>Registered in {@link com.dev.app.config.ShiroWebConfig} with an order
 * lower than the Shiro filter so headers are applied before any response body.</p>
 */
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Prevent MIME-type sniffing (IE / Chrome)
        response.setHeader("X-Content-Type-Options", "nosniff");

        // Block framing — clickjacking protection
        response.setHeader("X-Frame-Options", "DENY");

        // Legacy XSS protection (modern browsers use CSP instead)
        response.setHeader("X-XSS-Protection", "1; mode=block");

        // Limit referrer information leakage on cross-origin requests
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

        // Restrict where resources can be loaded from
        response.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");

        // Disable unnecessary browser features
        response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

        // Prevent caching of authenticated API responses
        response.setHeader("Cache-Control", "no-store");

        chain.doFilter(request, response);
    }
}
