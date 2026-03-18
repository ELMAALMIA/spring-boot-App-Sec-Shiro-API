package com.dev.app.service.impl;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.entities.User;
import com.dev.app.enums.RoleName;
import com.dev.app.exception.AccountLockedException;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.repository.UserRepository;
import com.dev.app.service.AuthService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
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
 * <p>All Shiro interactions (Subject.login, Subject.logout, role checks) are centralized
 * here — controllers never touch Shiro directly.</p>
 *
 * <p>Account lockout:</p>
 * <ul>
 *   <li>After {@value #MAX_FAILED_ATTEMPTS} consecutive failures → account locked for
 *       {@value #LOCK_DURATION_MINUTES} minutes</li>
 *   <li>Successful login resets failed-attempt counter</li>
 *   <li>Admin can unlock via {@code POST /api/v1/admin/users/{username}/unlock}</li>
 * </ul>
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    public static final int MAX_FAILED_ATTEMPTS = 5;
    static final int LOCK_DURATION_MINUTES = 15;

    private final UserRepository userRepository;

    public AuthServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {

        Subject subject = SecurityUtils.getSubject();

        if (subject.isAuthenticated()) {
            log.info("User '{}' is already authenticated", subject.getPrincipal());
            return buildLoginResponse("Already logged in", subject);
        }

        // Pre-check lockout from DB before delegating to Shiro
        Optional<User> maybeUser = userRepository.findByUsername(request.username());
        if (maybeUser.isPresent()) {
            User user = maybeUser.get();
            if (user.isLocked()) {
                log.warn("Login blocked — account locked: username={} lockedUntil={}",
                        request.username(), user.getLockedUntil());
                throw new AccountLockedException(user.getLockedUntil());
            }
        }

        UsernamePasswordToken token = new UsernamePasswordToken(
                request.username(),
                request.password()
        );

        try {
            subject.login(token);
            // On success: reset failed attempts
            maybeUser.ifPresent(user -> {
                user.setFailedAttempts(0);
                user.setLockedUntil(null);
                userRepository.save(user);
            });
            log.info("User '{}' logged in successfully", request.username());
            return buildLoginResponse("Login successful", subject);

        } catch (UnknownAccountException e) {
            log.warn("Login failed — unknown user: {}", request.username());
            throw new AuthenticationFailedException("Invalid credentials", e);

        } catch (IncorrectCredentialsException e) {
            // Increment failed attempts and potentially lock the account
            maybeUser.ifPresent(user -> {
                int attempts = user.getFailedAttempts() + 1;
                user.setFailedAttempts(attempts);
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES);
                    user.setLockedUntil(lockUntil);
                    log.warn("Account locked after {} failed attempts: username={} lockedUntil={}",
                            attempts, request.username(), lockUntil);
                } else {
                    log.warn("Login failed — wrong password: username={} failedAttempts={}/{}",
                            request.username(), attempts, MAX_FAILED_ATTEMPTS);
                }
                userRepository.save(user);
            });
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
        return new UserInfoResponse(username, roles.contains("ADMIN"), roles.contains("USER"), roles);
    }

    @Override
    public boolean isAuthenticated() {
        return SecurityUtils.getSubject().isAuthenticated();
    }

    /**
     * Unlocks a user account and resets their failed-attempt counter.
     * Called by admin endpoints.
     */
    @Transactional
    public void unlockAccount(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);
        log.info("Account unlocked by admin: username={}", username);
    }

    private LoginResponse buildLoginResponse(String message, Subject subject) {
        String username = (String) subject.getPrincipal();
        Set<String> roles = resolveRoles(subject);
        return new LoginResponse(message, username, roles.contains("ADMIN"), roles);
    }

    /**
     * Resolves the roles of the current subject by checking all known {@link RoleName} values.
     */
    private Set<String> resolveRoles(Subject subject) {
        return Arrays.stream(RoleName.values())
                .map(Enum::name)
                .filter(subject::hasRole)
                .collect(Collectors.toSet());
    }
}
