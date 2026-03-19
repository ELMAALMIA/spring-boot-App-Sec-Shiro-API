package com.dev.app.service.impl;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.entities.User;
import com.dev.app.enums.RoleName;
import com.dev.app.exception.AccountLockedException;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.exception.ResourceNotFoundException;
import com.dev.app.repository.UserRepository;
import com.dev.app.service.AuthService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.springframework.beans.factory.annotation.Value;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shiro-based implementation of {@link AuthService}.
 *
 * <p>All Shiro interactions (login, logout, role checks) are centralized here —
 * controllers never touch Shiro directly.</p>
 *
 * <h3>Account lockout</h3>
 * <ul>
 *   <li>After {@value #MAX_FAILED_ATTEMPTS} consecutive failures the account is locked
 *       for {@value #LOCK_DURATION_MINUTES} minutes.</li>
 *   <li>Failed-attempt increments are performed via a single {@code @Modifying} JPQL
 *       query ({@link UserRepository#recordFailedAttempt}) so the check-and-increment
 *       is atomic in the database — no TOCTOU race condition.</li>
 *   <li>Successful login resets the counter via {@link UserRepository#resetLoginAttempts}.</li>
 *   <li>Admin unlock: {@link #unlockAccount(String)}.</li>
 * </ul>
 *
 * <h3>Role checks</h3>
 * Uses {@link RoleName} enum everywhere — no raw string literals.
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    /** Default values — match app.security.* in application.properties. */
    public static final int MAX_FAILED_ATTEMPTS    = 5;
    public static final int LOCK_DURATION_MINUTES  = 15;

    private final UserRepository userRepository;
    private final int maxFailedAttempts;
    private final int lockDurationMinutes;

    public AuthServiceImpl(
            UserRepository userRepository,
            @Value("${app.security.max-failed-attempts:5}")  int maxFailedAttempts,
            @Value("${app.security.lock-duration-minutes:15}") int lockDurationMinutes) {
        this.userRepository       = userRepository;
        this.maxFailedAttempts    = maxFailedAttempts;
        this.lockDurationMinutes  = lockDurationMinutes;
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        Subject subject = SecurityUtils.getSubject();

        if (subject.isAuthenticated()) {
            log.info("User '{}' is already authenticated", subject.getPrincipal());
            return buildLoginResponse("Already logged in", subject);
        }

        // Pre-check: is the account locked?
        Optional<User> maybeUser = userRepository.findByUsername(request.username());
        if (maybeUser.isPresent() && maybeUser.get().isLocked()) {
            log.warn("Login blocked — account locked: username={} lockedUntil={}",
                    request.username(), maybeUser.get().getLockedUntil());
            throw new AccountLockedException(maybeUser.get().getLockedUntil());
        }

        UsernamePasswordToken token = new UsernamePasswordToken(
                request.username(),
                request.password()
        );

        try {
            subject.login(token);

            // Atomic reset — single UPDATE, no race window.
            maybeUser.ifPresent(u -> userRepository.resetLoginAttempts(u.getUsername()));

            log.info("User '{}' logged in successfully", request.username());
            return buildLoginResponse("Login successful", subject);

        } catch (UnknownAccountException e) {
            log.warn("Login failed — unknown account: {}", request.username());
            throw new AuthenticationFailedException("Invalid credentials", e);

        } catch (IncorrectCredentialsException e) {
            // Atomic increment + conditional lock in one SQL statement.
            userRepository.recordFailedAttempt(
                    request.username(),
                    maxFailedAttempts,
                    LocalDateTime.now().plusMinutes(lockDurationMinutes)
            );
            log.warn("Login failed — wrong password: username={}", request.username());
            throw new AuthenticationFailedException("Invalid credentials", e);

        } catch (LockedAccountException e) {
            log.warn("Login failed — Shiro account locked: {}", request.username());
            throw new AuthenticationFailedException("Account is locked", e);

        } catch (AuthenticationException e) {
            log.error("Login failed — unexpected error for user: {}", request.username(), e);
            throw new AuthenticationFailedException("Authentication failed", e);
        }
    }

    @Override
    public void logout() {
        Subject subject = SecurityUtils.getSubject();
        String principal = subject.isAuthenticated()
                ? (String) subject.getPrincipal()
                : "anonymous";
        subject.logout();
        log.info("User '{}' logged out", principal);
    }

    @Override
    public UserInfoResponse getCurrentUser() {
        Subject subject = SecurityUtils.getSubject();
        if (!subject.isAuthenticated()) {
            throw new AuthenticationFailedException("Not authenticated");
        }
        String username = (String) subject.getPrincipal();
        Set<String> roles = resolveRoles(subject);
        log.debug("Returning info for user '{}'", username);
        return new UserInfoResponse(
                username,
                roles.contains(RoleName.ADMIN.name()),
                roles.contains(RoleName.USER.name()),
                roles
        );
    }

    @Override
    public boolean isAuthenticated() {
        return SecurityUtils.getSubject().isAuthenticated();
    }

    @Override
    @Transactional
    public void unlockAccount(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", username));
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
        log.info("Account unlocked by admin: username={}", username);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private LoginResponse buildLoginResponse(String message, Subject subject) {
        String username = (String) subject.getPrincipal();
        Set<String> roles = resolveRoles(subject);
        return new LoginResponse(
                message,
                username,
                roles.contains(RoleName.ADMIN.name()),
                roles
        );
    }

    /**
     * Resolves the roles of the current Subject by checking every {@link RoleName} value.
     * Uses the enum — no raw string literals.
     */
    private Set<String> resolveRoles(Subject subject) {
        return Arrays.stream(RoleName.values())
                .map(Enum::name)
                .filter(subject::hasRole)
                .collect(Collectors.toSet());
    }
}
