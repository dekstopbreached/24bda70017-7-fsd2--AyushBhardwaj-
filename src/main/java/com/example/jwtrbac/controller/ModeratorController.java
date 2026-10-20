package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.ApiResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/mod")
@CrossOrigin(origins = "*", maxAge = 3600)
public class ModeratorController {

    /**
     * Endpoint accessible by users with ROLE_MODERATOR or ROLE_ADMIN.
     * Normal users (ROLE_USER) will be blocked with 403 Forbidden.
     */
    @GetMapping("/reports")
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getModerationQueue() {
        List<Map<String, Object>> reports = List.of(
                Map.of("id", "REP-101", "type", "Content Review", "priority", "MEDIUM", "status", "PENDING_REVIEW"),
                Map.of("id", "REP-102", "type", "Spam Detection", "priority", "HIGH", "status", "ACTION_REQUIRED"),
                Map.of("id", "REP-103", "type", "User Flag", "priority", "LOW", "status", "RESOLVED")
        );

        return ResponseEntity.ok(ApiResponse.ok("Moderation queue retrieved", reports));
    }
}
