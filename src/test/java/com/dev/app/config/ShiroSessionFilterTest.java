package com.dev.app.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ShiroSessionFilter}.
 *
 * Uses a real DefaultSecurityManager with a SimpleAccountRealm
 * (in-memory users) so we can test actual Shiro Subject behavior
 * without mocking internals.
 */
class ShiroSessionFilterTest {

    private ShiroSessionFilter filter;
    private DefaultSecurityManager securityManager;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        SimpleAccountRealm realm = new SimpleAccountRealm("test");
        realm.addAccount("admin", "admin123", "ADMIN", "USER");
        realm.addAccount("ayoub", "ayoub123", "USER");

        securityManager = new DefaultSecurityManager(realm);
        objectMapper = new ObjectMapper();
        filter = new ShiroSessionFilter(securityManager, objectMapper);
    }

    @AfterEach
    void tearDown() {
        ThreadContext.remove();
    }

    @Test
    void anonPath_hello_allowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/hello");
        request.setServletPath("/api/v1/hello");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
        assertEquals(200, response.getStatus());
    }

    @Test
    void anonPath_login_allowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setServletPath("/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void anonPath_swagger_allowed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/swagger-ui/index.html");
        request.setServletPath("/swagger-ui/index.html");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void protectedPath_unauthenticated_returns401() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/me");
        request.setServletPath("/api/v1/auth/me");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("Not authenticated"));
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void adminPath_unauthenticated_returns401() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/admin/dashboard");
        request.setServletPath("/api/v1/admin/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertEquals(401, response.getStatus());
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void threadContext_cleanedUp_afterRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/hello");
        request.setServletPath("/api/v1/hello");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        // ThreadContext must be clean after the filter runs
        assertNull(ThreadContext.getSubject());
        assertNull(ThreadContext.getSecurityManager());
    }

    @Test
    void sendJson_usesObjectMapper_safeForSpecialChars() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/me");
        request.setServletPath("/api/v1/auth/me");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        // Response body should be valid JSON (produced by ObjectMapper)
        String body = response.getContentAsString();
        assertDoesNotThrow(() -> objectMapper.readTree(body));
        assertEquals("application/json", response.getContentType());
    }
}
