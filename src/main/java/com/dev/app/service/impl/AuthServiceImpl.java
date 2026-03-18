package com.dev.app.service.impl;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.enums.RoleName;
import com.dev.app.exception.AuthenticationFailedException;
import com.dev.app.service.AuthService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shiro-based implementation of {@link AuthService}.
 *
 * All Shiro interactions (Subject.login, Subject.logout, role checks)
 * are centralized here — controllers never touch Shiro directly.
 */
@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);

    @Override
    public LoginResponse login(LoginRequest request) {

        Subject subject = SecurityUtils.getSubject();

        // Already authenticated ; return current session info
        if (subject.isAuthenticated()) {
            log.info("User '{}' is already authenticated", subject.getPrincipal());
            return buildLoginResponse("Already logged in", subject);
        }

        UsernamePasswordToken token = new UsernamePasswordToken(
                request.username(),
                request.password()
        );

        try {
            subject.login(token);
            log.info("User '{}' logged in successfully", request.username());
            return buildLoginResponse("Login successful", subject);

        } catch (UnknownAccountException e) {
            log.warn("Login failed — unknown user: {}", request.username());
            throw new AuthenticationFailedException("Unknown user", e);

        } catch (IncorrectCredentialsException e) {
            log.warn("Login failed — wrong password for user: {}", request.username());
            throw new AuthenticationFailedException("Wrong password", e);

        } catch (LockedAccountException e) {
            log.warn("Login failed — account locked: {}", request.username());
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
                roles.contains("ADMIN"),
                roles.contains("USER"),
                roles
        );
    }

    @Override
    public boolean isAuthenticated() {
        return SecurityUtils.getSubject().isAuthenticated();
    }


    private LoginResponse buildLoginResponse(String message, Subject subject) {
        String username = (String) subject.getPrincipal();
        Set<String> roles = resolveRoles(subject);
        return new LoginResponse(
                message,
                username,
                roles.contains("ADMIN"),
                roles
        );
    }

    /**
     * Resolves the roles of the current subject.
     * Checks all known RoleName enum values against the subject.
     */
    private Set<String> resolveRoles(Subject subject) {
        return Arrays.stream(RoleName.values())
                .map(Enum::name)
                .filter(subject::hasRole)
                .collect(Collectors.toSet());
    }
}
