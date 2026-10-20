package com.example.jwtrbac.dto;

import java.util.List;

public class AuthResponse {

    private String token;
    private String type = "Bearer";
    private String username;
    private String fullName;
    private String email;
    private List<String> roles;
    private long expiresInMs;

    public AuthResponse() {
    }

    public AuthResponse(String token, String username, String fullName, String email, List<String> roles, long expiresInMs) {
        this.token = token;
        this.type = "Bearer";
        this.username = username;
        this.fullName = fullName;
        this.email = email;
        this.roles = roles;
        this.expiresInMs = expiresInMs;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public long getExpiresInMs() {
        return expiresInMs;
    }

    public void setExpiresInMs(long expiresInMs) {
        this.expiresInMs = expiresInMs;
    }
}
