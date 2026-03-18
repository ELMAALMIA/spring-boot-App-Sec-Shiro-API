package com.dev.app.service;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.entities.User;
import com.dev.app.exception.AccountLockedException;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.repository.UserRepository;
import com.dev.app.service.impl.AuthServiceImpl;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
    private UserRepository mockUserRepository;

    @BeforeEach
    void setUp() {
        mockUserRepository = mock(UserRepository.class);
        authService = new AuthServiceImpl(mockUserRepository);

        mockSubject = mock(Subject.class);
        DefaultSecurityManager mockSecurityManager = mock(DefaultSecurityManager.class);

        ThreadContext.bind(mockSecurityManager);
        ThreadContext.bind(mockSubject);

        // Default: user not found in DB (no lockout side effects)
        when(mockUserRepository.findByUsername(any())).thenReturn(Optional.empty());
    }

    @AfterEach
    void tearDown() {
        ThreadContext.remove();
    }

    // ── login() ──────────────────────────────────────────────────────────

    @Test
    void login_success_returnsLoginResponse() {
        when(mockSubject.isAuthenticated()).thenReturn(false).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");
        when(mockSubject.hasRole("ADMIN")).thenReturn(true);
        when(mockSubject.hasRole("USER")).thenReturn(true);

        LoginResponse response = authService.login(new LoginRequest("admin", "admin123"));

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

        LoginResponse response = authService.login(new LoginRequest("admin", "admin123"));

        assertEquals("Already logged in", response.message());
        verify(mockSubject, never()).login(any());
    }

    @Test
    void login_unknownUser_throwsAuthenticationFailed() {
        when(mockSubject.isAuthenticated()).thenReturn(false);
        doThrow(new UnknownAccountException()).when(mockSubject).login(any());

        AuthenticationFailedException ex = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(new LoginRequest("unknown", "pass"))
        );
        assertEquals("Invalid credentials", ex.getMessage());
    }

    @Test
    void login_wrongPassword_throwsAuthenticationFailed() {
        when(mockSubject.isAuthenticated()).thenReturn(false);
        doThrow(new IncorrectCredentialsException()).when(mockSubject).login(any());

        AuthenticationFailedException ex = assertThrows(
                AuthenticationFailedException.class,
                () -> authService.login(new LoginRequest("admin", "wrong"))
        );
        assertEquals("Invalid credentials", ex.getMessage());

        // Atomic increment must be called on wrong password
        verify(mockUserRepository).recordFailedAttempt(
                eq("admin"),
                eq(AuthServiceImpl.MAX_FAILED_ATTEMPTS),
                any(LocalDateTime.class)
        );
    }

    @Test
    void login_lockedAccount_throwsAccountLockedException() {
        User lockedUser = new User();
        lockedUser.setUsername("ayoub");
        lockedUser.setLockedUntil(LocalDateTime.now().plusMinutes(10));

        when(mockUserRepository.findByUsername("ayoub")).thenReturn(Optional.of(lockedUser));
        when(mockSubject.isAuthenticated()).thenReturn(false);

        assertThrows(AccountLockedException.class,
                () -> authService.login(new LoginRequest("ayoub", "ayoub123")));

        // Subject.login must not be called for locked accounts
        verify(mockSubject, never()).login(any());
    }

    @Test
    void login_success_resetsFailedAttempts() {
        User user = new User();
        user.setUsername("admin");
        user.setFailedAttempts(3);

        when(mockUserRepository.findByUsername("admin")).thenReturn(Optional.of(user));
        when(mockSubject.isAuthenticated()).thenReturn(false).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");
        when(mockSubject.hasRole(any())).thenReturn(false);

        authService.login(new LoginRequest("admin", "admin123"));

        verify(mockUserRepository).resetLoginAttempts("admin");
    }

    // ── logout() ──────────────────────────────────────────────────────────

    @Test
    void logout_callsSubjectLogout() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        when(mockSubject.getPrincipal()).thenReturn("admin");

        authService.logout();

        verify(mockSubject).logout();
    }

    // ── getCurrentUser() ──────────────────────────────────────────────────

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

        assertThrows(AuthenticationFailedException.class, () -> authService.getCurrentUser());
    }

    // ── isAuthenticated() ─────────────────────────────────────────────────

    @Test
    void isAuthenticated_returnsSubjectState() {
        when(mockSubject.isAuthenticated()).thenReturn(true);
        assertTrue(authService.isAuthenticated());

        when(mockSubject.isAuthenticated()).thenReturn(false);
        assertFalse(authService.isAuthenticated());
    }
}
