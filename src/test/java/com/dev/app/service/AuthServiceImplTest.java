package com.dev.app.service;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.service.impl.AuthServiceImpl;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuthServiceImpl}.
 *
 * Shiro's Subject is mocked via ThreadContext binding so that
 * SecurityUtils.getSubject() returns our controlled mock.
 */
class AuthServiceImplTest {

    private AuthServiceImpl authService;
    private Subject mockSubject;
    private DefaultSecurityManager mockSecurityManager;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl();

        mockSubject = mock(Subject.class);
        mockSecurityManager = mock(DefaultSecurityManager.class);

        // Bind to ThreadContext so SecurityUtils.getSubject() works
        ThreadContext.bind(mockSecurityManager);
        ThreadContext.bind(mockSubject);
    }

    @AfterEach
    void tearDown() {
        ThreadContext.remove();
    }

    // ── login() tests ─────────────────────────────────────────────────────

    @Test
    void login_success_returnsLoginResponse() {
        when(mockSubject.isAuthenticated()).thenReturn(false).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");
        when(mockSubject.hasRole("ADMIN")).thenReturn(true);
        when(mockSubject.hasRole("USER")).thenReturn(true);

        LoginRequest request = new LoginRequest("admin", "admin123");
        LoginResponse response = authService.login(request);

        assertEquals("Login successful", response.message());
        assertEquals("admin", response.username());
        assertTrue(response.isAdmin());
        assertTrue(response.roles().contains("ADMIN"));
        verify(mockSubject).login(any(UsernamePasswordToken.class));
    }

    @Test
    void login_alreadyAuthenticated_returnsAlreadyLoggedIn() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");
        when(mockSubject.hasRole("ADMIN")).thenReturn(true);
        when(mockSubject.hasRole("USER")).thenReturn(false);

        LoginRequest request = new LoginRequest("admin", "admin123");
        LoginResponse response = authService.login(request);

        assertEquals("Already logged in", response.message());
        verify(mockSubject, never()).login(any());
    }

    @Test
    void login_unknownUser_throwsAuthenticationFailed() {
        when(mockSubject.isAuthenticated()).thenReturn(false);
        doThrow(new UnknownAccountException("test")).when(mockSubject).login(any());

        LoginRequest request = new LoginRequest("unknown", "pass");

        AuthenticationFailedException ex = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(request)
        );
        assertEquals("Unknown user", ex.getMessage());
    }

    @Test
    void login_wrongPassword_throwsAuthenticationFailed() {
        when(mockSubject.isAuthenticated()).thenReturn(false);
        doThrow(new IncorrectCredentialsException("test")).when(mockSubject).login(any());

        LoginRequest request = new LoginRequest("admin", "wrong");

        AuthenticationFailedException ex = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(request)
        );
        assertEquals("Wrong password", ex.getMessage());
    }

    // ── logout() tests ────────────────────────────────────────────────────

    @Test
    void logout_callsSubjectLogout() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");

        authService.logout();

        verify(mockSubject).logout();
    }

    // ── getCurrentUser() tests ────────────────────────────────────────────

    @Test
    void getCurrentUser_authenticated_returnsUserInfo() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("ayoub");
        when(mockSubject.hasRole("ADMIN")).thenReturn(false);
        when(mockSubject.hasRole("USER")).thenReturn(true);

        UserInfoResponse response = authService.getCurrentUser();

        assertEquals("ayoub", response.username());
        assertFalse(response.isAdmin());
        assertTrue(response.isUser());
        assertTrue(response.roles().contains("USER"));
        assertFalse(response.roles().contains("ADMIN"));
    }

    @Test
    void getCurrentUser_notAuthenticated_throwsException() {
        when(mockSubject.isAuthenticated()).thenReturn(false);

        assertThrows(
                AuthenticationFailedException.class,
                () -> authService.getCurrentUser()
        );
    }

    // ── isAuthenticated() tests ───────────────────────────────────────────

    @Test
    void isAuthenticated_returnsSubjectState() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        assertTrue(authService.isAuthenticated());

        when(mockSubject.isAuthenticated()).thenReturn(false);
        assertFalse(authService.isAuthenticated());
    }
}
