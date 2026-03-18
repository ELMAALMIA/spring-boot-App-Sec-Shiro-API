package com.dev.app.service;

import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.UserInfoResponse;

/**
 * Authentication & authorization service contract.
 */
public interface AuthService {

    /**
     * Authenticate a user and return login details.
     *
     * @param request validated login credentials
     * @return login response with user info and roles
     */
    LoginResponse login(LoginRequest request);

    /**
     * Log out the current user (invalidate session).
     */
    void logout();

    /**
     * Get the current authenticated user's info.
     *
     * @return user info with roles
     */
    UserInfoResponse getCurrentUser();

    /**
     * Check if the current thread's Subject is authenticated.
     */
    boolean isAuthenticated();
}
