package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.ApiResponse;
import com.example.jwtrbac.security.CustomUserDetails;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    /**
     * Endpoint restricted to users with ROLE_USER or ROLE_ADMIN.
     */
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserProfile(@AuthenticationPrincipal CustomUserDetails userDetails) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("id", userDetails.getId());
        profile.put("username", userDetails.getUsername());
        profile.put("fullName", userDetails.getFullName());
        profile.put("email", userDetails.getEmail());
        profile.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        profile.put("status", "Active Member");
        profile.put("message", "Welcome to your protected user profile!");

        return ResponseEntity.ok(ApiResponse.ok("User profile fetched successfully", profile));
    }

    /**
     * User dashboard restricted to ROLE_USER or ROLE_ADMIN.
     */
    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUserDashboard(@AuthenticationPrincipal CustomUserDetails userDetails) {
        Map<String, Object> dashboard = new HashMap<>();
        dashboard.put("user", userDetails.getUsername());
        dashboard.put("notifications", List.of(
                "Welcome to the JWT Secure API Portal",
                "Your session is verified with a tamper-proof Bearer token",
                "RBAC is actively enforced at the method level using @PreAuthorize"
        ));
        dashboard.put("accessibleModules", List.of("Profile", "Activity Log", "Settings"));
        dashboard.put("serverTimestamp", Instant.now().toString());

        return ResponseEntity.ok(ApiResponse.ok("User dashboard loaded", dashboard));
    }
}
