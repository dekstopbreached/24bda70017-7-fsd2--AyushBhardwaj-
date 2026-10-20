package com.example.jwtrbac.model;

/**
 * Enumeration representing available system roles for Role-Based Access Control (RBAC).
 * Spring Security's convention prefixes roles with 'ROLE_'.
 */
public enum Role {
    ROLE_USER,
    ROLE_MODERATOR,
    ROLE_ADMIN;

    public String getRoleName() {
        return name();
    }
}
