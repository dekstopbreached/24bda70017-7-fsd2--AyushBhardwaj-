package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
@CrossOrigin(origins = "*", maxAge = 3600)
public class PublicController {

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, Object>>> checkHealth() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "Secure Backend APIs with JWT & RBAC");
        health.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(ApiResponse.ok("Service is running smoothly", health));
    }

    @GetMapping("/info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("description", "Secure Backend APIs using JWT authentication and role-based authorization");
        info.put("authenticationType", "Stateless JSON Web Token (JWT) Bearer Token");
        info.put("rolesSupported", List.of("ROLE_USER", "ROLE_MODERATOR", "ROLE_ADMIN"));
        info.put("endpoints", Map.of(
                "public", List.of("/api/public/health", "/api/public/info", "/api/auth/login", "/api/auth/register"),
                "user", List.of("/api/user/profile", "/api/user/dashboard"),
                "moderator", List.of("/api/mod/reports"),
                "admin", List.of("/api/admin/users", "/api/admin/system-status", "/api/admin/grant-role")
        ));
        info.put("preLoadedCredentials", List.of(
                Map.of("username", "admin", "password", "admin123", "roles", List.of("ROLE_ADMIN", "ROLE_USER")),
                Map.of("username", "user", "password", "user123", "roles", List.of("ROLE_USER")),
                Map.of("username", "moderator", "password", "mod123", "roles", List.of("ROLE_MODERATOR"))
        ));
        return ResponseEntity.ok(ApiResponse.ok("API information retrieved successfully", info));
    }
}
