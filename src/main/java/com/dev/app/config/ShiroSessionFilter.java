package com.dev.app.config;

import com.dev.app.enums.RoleName;
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
 * <p>Replaces shiro-web's AbstractShiroFilter (javax.servlet) with a Spring
 * {@link OncePerRequestFilter} (jakarta.servlet) that handles:</p>
 * <ol>
 *   <li>Bind SecurityManager + Subject to the current thread (ThreadContext)</li>
 *   <li>Restore the authenticated session from the HTTP session (if any)</li>
 *   <li>Enforce URL-based access rules (anon / authc / admin)</li>
 *   <li>After the request, persist auth state back to the HTTP session</li>
 *   <li>Session fixation prevention: rotate session ID on login</li>
 *   <li>Always clean up the ThreadContext (even on exception)</li>
 * </ol>
 *
 * <h3>ThreadContext safety</h3>
 * Both {@code ThreadContext.bind()} calls are inside the {@code try} block,
 * so the {@code finally} block's {@code ThreadContext.remove()} is always
 * guaranteed to pair with them — no ThreadLocal leak on exception paths.
 *
 * <h3>Session fixation prevention</h3>
 * When a request transitions from unauthenticated → authenticated (i.e. a login),
 * the old session is invalidated and a fresh session with a new ID is created.
 * The servlet container issues a new {@code Set-Cookie: JSESSIONID} header via
 * {@code request.getSession(true)}.
 */
public class ShiroSessionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ShiroSessionFilter.class);

    /** HTTP session key where the authenticated principal collection is stored. */
    private static final String SESSION_KEY = "SHIRO_PRINCIPALS";

    /** Paths that require NO authentication. */
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

        // Step 1: Create / retrieve the HTTP session BEFORE the response is committed.
        //   Creating it later (in finally) would fail with
        //   "Cannot create a session after the response has been committed".
        HttpSession session = request.getSession(true);

        // Step 2: Restore Subject from HTTP session.
        PrincipalCollection pc = (PrincipalCollection) session.getAttribute(SESSION_KEY);

        Subject subject = new Subject.Builder(securityManager)
                .principals(pc != null ? pc : new SimplePrincipalCollection())
                .authenticated(pc != null)
                .buildSubject();

        /*
         * CRITICAL FIX — ThreadContext leak prevention:
         * Both bind() calls are INSIDE the try block.
         * The finally block's ThreadContext.remove() is therefore always
         * paired with these binds, even if an exception is thrown before
         * chain.doFilter() is reached.
         */
        try {
            ThreadContext.bind(securityManager);
            ThreadContext.bind(subject);

            // Step 3: Resolve path (MockMvc may return empty servletPath).
            String path = request.getServletPath();
            if (path == null || path.isEmpty()) {
                path = request.getRequestURI();
            }

            // Step 4: Apply access rules.
            if (!isAnon(path)) {
                if (!subject.isAuthenticated()) {
                    log.warn("Unauthenticated access blocked: {} {}", request.getMethod(), path);
                    sendJson(response, 401, "Not authenticated — POST /api/v1/auth/login first");
                    return;
                }

                if (isAdminPath(path) && !subject.hasRole(RoleName.ADMIN.name())) {
                    log.warn("Unauthorized access blocked: user='{}' path={}",
                            subject.getPrincipal(), path);
                    sendJson(response, 403, "Access denied — ADMIN role required");
                    return;
                }
            }

            // Step 5: Continue the request.
            chain.doFilter(request, response);

        } finally {
            // Step 6: Persist / rotate session, then clean up ThreadContext.
            persistSession(request, session, pc, ThreadContext.getSubject());
            ThreadContext.remove();
        }
    }

    /**
     * Persists the post-request authentication state to the HTTP session.
     *
     * <p>If the subject transitioned from unauthenticated → authenticated (a login event),
     * the old session is invalidated and a fresh session is created — preventing session
     * fixation attacks where an attacker pre-planted a known session ID.</p>
     */
    private void persistSession(HttpServletRequest request,
                                HttpSession originalSession,
                                PrincipalCollection originalPc,
                                Subject current) {
        boolean wasAuthenticated = originalPc != null;
        boolean isNowAuthenticated = current != null && current.isAuthenticated();

        if (isNowAuthenticated) {
            if (!wasAuthenticated) {
                // LOGIN event detected — rotate session ID (session fixation prevention).
                PrincipalCollection principals = current.getPrincipals();
                try {
                    originalSession.invalidate();
                } catch (IllegalStateException ignored) {
                    // Already invalidated — safe to continue.
                }
                HttpSession newSession = request.getSession(true);
                newSession.setAttribute(SESSION_KEY, principals);
                log.debug("Session rotated on login — fixation prevention active");
            } else {
                // Already authenticated — just refresh the stored principals.
                originalSession.setAttribute(SESSION_KEY, current.getPrincipals());
            }
        } else {
            // Logged out or never authenticated — clear session attribute.
            try {
                originalSession.removeAttribute(SESSION_KEY);
            } catch (IllegalStateException ignored) {
                // Session was invalidated (e.g. by logout) — nothing to clear.
            }
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

    private void sendJson(HttpServletResponse response, int status, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                objectMapper.writeValueAsString(Map.of("error", message))
        );
    }
}
