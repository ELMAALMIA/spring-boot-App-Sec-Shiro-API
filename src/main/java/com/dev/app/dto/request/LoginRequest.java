package com.dev.app.dto.request;

import com.dev.app.annotation.Sensitive;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for POST /auth/login.
 *
 * <h3>Password policy</h3>
 * <ul>
 *   <li>Minimum 8 characters (NIST SP 800-63B baseline)</li>
 *   <li>At least one uppercase letter, one lowercase letter,
 *       one digit, and one special character</li>
 *   <li>Maximum 100 characters (prevents DoS via hash computation)</li>
 * </ul>
 */
public record LoginRequest(

        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        @Pattern(
                regexp = "^[a-zA-Z0-9_-]+$",
                message = "Username may only contain letters, digits, underscores and hyphens"
        )
        String username,

        @Sensitive
        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100, message = "Password must be between 8 and 100 characters")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^a-zA-Z0-9]).+$",
                message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
        )
        String password
) {}
