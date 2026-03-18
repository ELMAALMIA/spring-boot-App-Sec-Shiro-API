package com.dev.app.controller;

import com.dev.app.dto.response.UserInfoResponse;
import com.dev.app.service.AuthService;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Admin-only endpoints.
 *
 * Protected at two levels:
 *  1. URL filter: /api/v1/admin/** requires authentication + ADMIN role (ShiroSessionFilter)
 *  2. Method annotation: @RequiresRoles("ADMIN") (double-check via AOP)
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final AuthService authService;

    public AdminController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * GET /api/v1/admin/dashboard
     * Only accessible to users with role ADMIN.
     */
    @GetMapping("/dashboard")
    @RequiresRoles("ADMIN")
    public ResponseEntity<Map<String, Object>> dashboard() {
        UserInfoResponse user = authService.getCurrentUser();
        return ResponseEntity.ok(Map.of(
                "message", "Welcome to the Admin Dashboard",
                "user", user.username(),
                "roles", user.roles()
        ));
    }
}
