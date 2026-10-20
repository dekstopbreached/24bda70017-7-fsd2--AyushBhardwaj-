package com.example.jwtrbac.model;

import java.util.HashSet;
import java.util.Set;

/**
 * Domain model representing a user in the system.
 */
public class User {

    private String id;
    private String username;
    private String password;
    private String fullName;
    private String email;
    private Set<Role> roles = new HashSet<>();

    public User() {
    }

    public User(String id, String username, String password, String fullName, String email, Set<Role> roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.fullName = fullName;
        this.email = email;
        this.roles = (roles != null) ? roles : new HashSet<>();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
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

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
