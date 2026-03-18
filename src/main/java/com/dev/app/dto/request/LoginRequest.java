package com.dev.app.dto.request;

import com.dev.app.annotation.Sensitive;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for POST /auth/login.
 */
public record LoginRequest(

        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        String username,

        @Sensitive
        @NotBlank(message = "Password is required")
        @Size(min = 4, max = 100, message = "Password must be between 4 and 100 characters")
        String password
) {}
