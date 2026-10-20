package com.example.jwtrbac.controller;

import com.example.jwtrbac.dto.ApiResponse;
import com.example.jwtrbac.dto.AuthRequest;
import com.example.jwtrbac.dto.AuthResponse;
import com.example.jwtrbac.dto.RegisterRequest;
import com.example.jwtrbac.model.Role;
import com.example.jwtrbac.model.User;
import com.example.jwtrbac.repository.UserRepository;
import com.example.jwtrbac.security.CustomUserDetails;
import com.example.jwtrbac.security.JwtUtils;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthController(AuthenticationManager authenticationManager,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          JwtUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    /**
     * Authenticate user with username and password, then return JWT token and role details.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> authenticateUser(@Valid @RequestBody AuthRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        AuthResponse authResponse = new AuthResponse(
                jwt,
                userDetails.getUsername(),
                userDetails.getFullName(),
                userDetails.getEmail(),
                roles,
                jwtUtils.getJwtExpirationMs()
        );

        return ResponseEntity.ok(ApiResponse.ok("Authentication successful", authResponse));
    }

    /**
     * Register a new user with chosen roles (defaults to ROLE_USER if none supplied).
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Map<String, Object>>> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Error: Username '" + registerRequest.getUsername() + "' is already taken!"));
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Error: Email '" + registerRequest.getEmail() + "' is already in use!"));
        }

        Set<Role> roles = registerRequest.getRoles();
        if (roles == null || roles.isEmpty()) {
            roles = new HashSet<>(Collections.singletonList(Role.ROLE_USER));
        }

        User newUser = new User(
                UUID.randomUUID().toString(),
                registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword()),
                registerRequest.getFullName(),
                registerRequest.getEmail(),
                roles
        );

        userRepository.save(newUser);

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("username", newUser.getUsername());
        responseData.put("email", newUser.getEmail());
        responseData.put("roles", newUser.getRoles().stream().map(Role::name).collect(Collectors.toList()));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("User registered successfully!", responseData));
    }

    /**
     * Get currently authenticated user's profile and authorities.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        if (userDetails == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("No authenticated user found"));
        }

        Map<String, Object> data = new HashMap<>();
        data.put("id", userDetails.getId());
        data.put("username", userDetails.getUsername());
        data.put("fullName", userDetails.getFullName());
        data.put("email", userDetails.getEmail());
        data.put("authorities", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return ResponseEntity.ok(ApiResponse.ok("Current user profile retrieved successfully", data));
    }
}
