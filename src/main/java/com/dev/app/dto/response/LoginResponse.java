package com.dev.app.dto.response;

import java.util.Set;

/**
 * Response DTO returned after successful login.
 */
public record LoginResponse(
        String message,
        String username,
        boolean isAdmin,
        Set<String> roles
) {}
