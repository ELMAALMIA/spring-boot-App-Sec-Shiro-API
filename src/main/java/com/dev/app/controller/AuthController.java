package com.dev.app.controller;

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
 * All Shiro interaction is delegated to {@link AuthService} —
 * the controller only handles HTTP request/response mapping.
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
     */
    @PostMapping("/login")
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
     * GET /api/v1/auth/me — returns current session info (requires authentication)
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> me() {
        return ResponseEntity.ok(authService.getCurrentUser());
    }
}
