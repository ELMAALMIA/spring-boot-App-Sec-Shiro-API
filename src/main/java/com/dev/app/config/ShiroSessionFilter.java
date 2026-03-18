package com.dev.app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

/**
 * Jakarta-native Shiro security filter.
 *
 * Replaces shiro-web's AbstractShiroFilter (which uses javax.servlet)
 * with a Spring OncePerRequestFilter (jakarta.servlet) that does the same job:
 *
 *  1. Binds SecurityManager + Subject to the current thread (ThreadContext)
 *  2. Restores the authenticated session from the HTTP session (if any)
 *  3. Enforces URL-based access rules (anon / authc / admin)
 *  4. After the request, persists auth state back to the HTTP session
 *  5. Cleans up the ThreadContext (always, even on error)
 *
 * How session state is kept between requests:
 *   On login  → AuthController calls subject.login(token)
 *              → filter saves subject.getPrincipals() to HTTP session
 *   On request → filter reads principals from HTTP session
 *              → rebuilds the Subject with those principals
 *              → binds it to ThreadContext so SecurityUtils.getSubject() works
 *   On logout  → AuthController calls subject.logout()
 *              → filter sees !isAuthenticated() and removes from HTTP session
 */
public class ShiroSessionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ShiroSessionFilter.class);

    /** HTTP session key where the authenticated principal is stored */
    private static final String SESSION_KEY = "SHIRO_PRINCIPALS";

    /** Paths that require NO authentication (exact match) */
    private static final Set<String> ANON_PATHS = Set.of(
            "/api/v1/hello",
            "/api/v1/auth/login",
            "/api/v1/auth/logout"
    );

    private final SecurityManager securityManager;
    private final ObjectMapper objectMapper;

    public ShiroSessionFilter(SecurityManager securityManager, ObjectMapper objectMapper) {
        this.securityManager = securityManager;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        //  1: Bind SecurityManager to thread
        ThreadContext.bind(securityManager);

        //  Step 2: Ensure HTTP session exists BEFORE the response is committed.
        //    Creating a session later (in the finally block) would fail with
        //    "Cannot create a session after the response has been committed"
        //    because the JSESSIONID cookie can only be set while headers are open.
        HttpSession session = request.getSession(true);

        //  Step 3: Restore Subject from HTTP session
        PrincipalCollection pc = (PrincipalCollection) session.getAttribute(SESSION_KEY);

        Subject subject = new Subject.Builder(securityManager)
                .principals(pc != null ? pc : new SimplePrincipalCollection())
                .authenticated(pc != null)
                .buildSubject();

        ThreadContext.bind(subject);

        try {
            // getServletPath() may be empty in MockMvc — fall back to requestURI
            String path = request.getServletPath();
            if (path == null || path.isEmpty()) {
                path = request.getRequestURI();
            }

            // Step 4: Apply access rules
            if (!isAnon(path)) {

                if (!subject.isAuthenticated()) {
                    log.warn("Unauthenticated access blocked: {} {}", request.getMethod(), path);
                    sendJson(response, 401, "Not authenticated — POST /api/v1/auth/login first");
                    return;
                }

                if (isAdminPath(path) && !subject.hasRole("ADMIN")) {
                    log.warn("Unauthorized access blocked: user='{}' path={}",
                            subject.getPrincipal(), path);
                    sendJson(response, 403, "Access denied — ADMIN role required");
                    return;
                }
            }

            // Step 5: Continue the request
            chain.doFilter(request, response);

        } finally {
            //  Step 6: Persist & clear auth state in HTTP session
            //    Session already exists (created in Step 2), so this is safe
            //    even after the response has been committed.
            Subject current = ThreadContext.getSubject();
            if (current != null && current.isAuthenticated()) {
                session.setAttribute(SESSION_KEY, current.getPrincipals());
            } else {
                session.removeAttribute(SESSION_KEY);
            }

            // Step 7: Always clean up ThreadContext
            ThreadContext.remove();
        }
    }


    private boolean isAnon(String path) {
        return ANON_PATHS.contains(path)
                || path.startsWith("/h2-console")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs");
    }

    private boolean isAdminPath(String path) {
        return path.startsWith("/api/v1/admin");
    }

    /**
     * Writes a JSON error body using Jackson — safe for all characters in {@code message}.
     */
    private void sendJson(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                objectMapper.writeValueAsString(Map.of("error", message))
        );
    }
}
