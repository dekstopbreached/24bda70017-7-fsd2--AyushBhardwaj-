package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.ApiResponse;
import com.example.jwtrbac.model.Role;
import com.example.jwtrbac.model.User;
import com.example.jwtrbac.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AdminController {

    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Endpoint restricted EXCLUSIVELY to users with ROLE_ADMIN.
     * Lists all registered users in the system.
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<List<Map<String, Object>>>> getAllUsers() {
        List<Map<String, Object>> userList = userRepository.findAll().stream().map(user -> {
            Map<String, Object> map = new HashMap<>();
            map.put("id", user.getId());
            map.put("username", user.getUsername());
            map.put("fullName", user.getFullName());
            map.put("email", user.getEmail());
            map.put("roles", user.getRoles().stream().map(Role::name).collect(Collectors.toList()));
            return map;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(ApiResponse.ok("Admin: All users retrieved successfully", userList));
    }

    /**
     * Endpoint restricted to ROLE_ADMIN.
     * Returns sensitive system internals and JVM performance metrics.
     */
    @GetMapping("/system-status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSystemStatus() {
        Runtime runtime = Runtime.getRuntime();
        Map<String, Object> status = new HashMap<>();
        status.put("totalMemoryMb", runtime.totalMemory() / (1024 * 1024));
        status.put("freeMemoryMb", runtime.freeMemory() / (1024 * 1024));
        status.put("maxMemoryMb", runtime.maxMemory() / (1024 * 1024));
        status.put("availableProcessors", runtime.availableProcessors());
        status.put("jvmUptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
        status.put("registeredUsersCount", userRepository.findAll().size());
        status.put("securityPolicy", "Strict RBAC with Method-Level @PreAuthorize and Stateless JWT");
        status.put("timestamp", Instant.now().toString());

        return ResponseEntity.ok(ApiResponse.ok("Admin: System diagnostics retrieved", status));
    }

    /**
     * Endpoint restricted to ROLE_ADMIN.
     * Grants an additional role to an existing user.
     */
    @PostMapping("/grant-role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Map<String, Object>>> grantRole(
            @RequestParam String username,
            @RequestParam Role role) {

        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("User not found: " + username));
        }

        User user = optionalUser.get();
        user.getRoles().add(role);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("username", user.getUsername());
        result.put("updatedRoles", user.getRoles().stream().map(Role::name).collect(Collectors.toList()));

        return ResponseEntity.ok(ApiResponse.ok("Role " + role + " granted to " + username, result));
    }
}
