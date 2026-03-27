package com.dev.app.controller;

import com.dev.app.annotation.CurrentUser;
import com.dev.app.annotation.IsAdmin;
import com.dev.app.annotation.PermissionCheck;
import com.dev.app.annotation.RateLimit;
import com.dev.app.dto.response.MessageResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.service.AuthService;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Admin-only endpoints.
 *
 * <p>Protected at two levels:</p>
 * <ol>
 *   <li>URL filter: {@code /api/v1/admin/**} requires auth + ADMIN role
 *       ({@link com.dev.app.config.ShiroSessionFilter})</li>
 *   <li>Method annotation: {@link IsAdmin} via {@link com.dev.app.config.SecurityAspect}
 *       (AOP double-check)</li>
 * </ol>
 *
 * <p>Depends only on the {@link AuthService} <em>interface</em> — never on
 * {@code AuthServiceImpl} directly, satisfying the Dependency Inversion Principle.</p>
 */
@RestController
@RequestMapping("/api/v1/admin")
@Validated
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * GET /api/v1/admin/dashboard
     */
    @GetMapping("/dashboard")
    @IsAdmin
    @RateLimit(requests = 30, windowSeconds = 60)
    public ResponseEntity<Map<String, Object>> dashboard(@CurrentUser String username) {
        UserInfoResponse user = authService.getCurrentUser();
        return ResponseEntity.ok(Map.of(
                "message", "Welcome to the Admin Dashboard",
                "user", username,
                "roles", user.roles()
        ));
    }

    /**
     * POST /api/v1/admin/users/{username}/unlock
     *
     * <p>Unlocks a locked account and resets its failed-attempt counter.
     * Requires {@code admin:manage} permission (ADMIN role has this by default).</p>
     */
    @PostMapping("/users/{username}/unlock")
    @IsAdmin
    @PermissionCheck("admin:manage")
    @RateLimit(requests = 10, windowSeconds = 60)
    public ResponseEntity<MessageResponse> unlockUser(
            @PathVariable
            @NotBlank(message = "Username must not be blank")
            @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
            @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Username contains invalid characters")
            String username,
            @CurrentUser String adminUsername) {
        authService.unlockAccount(username);
        return ResponseEntity.ok(
                new MessageResponse("Account '" + username + "' unlocked by " + adminUsername)
        );
    }
}
