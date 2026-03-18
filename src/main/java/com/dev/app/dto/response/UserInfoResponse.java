package com.dev.app.dto.response;

import java.util.Set;

/**
 * Response DTO for GET /api/v1/auth/me — current session info.
 */
public record UserInfoResponse(
        String username,
        boolean isAdmin,
        boolean isUser,
        Set<String> roles
) {}
