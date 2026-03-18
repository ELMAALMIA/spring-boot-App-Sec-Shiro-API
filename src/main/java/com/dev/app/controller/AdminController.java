package com.dev.app.controller;

import com.dev.app.annotation.CurrentUser;
import com.dev.app.annotation.IsAdmin;
import com.dev.app.annotation.PermissionCheck;
import com.dev.app.dto.response.MessageResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.service.AuthService;
import com.dev.app.service.impl.AuthServiceImpl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Admin-only endpoints.
 *
 * <p>Protected at two levels:</p>
 * <ol>
 *   <li>URL filter: {@code /api/v1/admin/**} requires auth + ADMIN role ({@link com.dev.app.config.ShiroSessionFilter})</li>
 *   <li>Method annotation: {@link IsAdmin} via {@link com.dev.app.config.SecurityAspect} (AOP double-check)</li>
 * </ol>
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final AuthService authService;
    private final AuthServiceImpl authServiceImpl;

    public AdminController(AuthService authService, AuthServiceImpl authServiceImpl) {
        this.authService = authService;
        this.authServiceImpl = authServiceImpl;
    }

    /**
     * GET /api/v1/admin/dashboard
     */
    @GetMapping("/dashboard")
    @IsAdmin
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
    public ResponseEntity<MessageResponse> unlockUser(@PathVariable String username,
                                                       @CurrentUser String adminUsername) {
        authServiceImpl.unlockAccount(username);
        return ResponseEntity.ok(
                new MessageResponse("Account '" + username + "' unlocked by " + adminUsername)
        );
    }
}
