package com.dev.app.controller;

import com.dev.app.annotation.CurrentUser;
import com.dev.app.annotation.IsUser;
import com.dev.app.annotation.RateLimit;
import com.dev.app.dto.request.LoginRequest;
import com.dev.app.dto.response.LoginResponse;
import com.dev.app.dto.response.MessageResponse;
import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication endpoints.
 *
 * <p>All Shiro interaction is delegated to {@link AuthService} —
 * the controller only handles HTTP request/response mapping.</p>
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * POST /api/v1/auth/login
     * Body: { "username": "admin", "password": "admin123" }
     *
     * Rate limited: 10 attempts per minute per IP (OWASP API4 — brute-force protection).
     */
    @PostMapping("/login")
    @RateLimit(requests = 10, windowSeconds = 60)
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * POST /api/v1/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout() {
        authService.logout();
        return ResponseEntity.ok(new MessageResponse("Logged out successfully"));
    }

    /**
     * GET /api/v1/auth/me — returns current session info (requires USER role).
     *
     * Demonstrates {@link CurrentUser} resolving the principal without calling SecurityUtils,
     * and {@link IsUser} enforcing role via AOP.
     */
    @GetMapping("/me")
    @IsUser
    @RateLimit(requests = 30, windowSeconds = 60)
    public ResponseEntity<UserInfoResponse> me(@CurrentUser String username) {
        return ResponseEntity.ok(authService.getCurrentUser());
    }
}
