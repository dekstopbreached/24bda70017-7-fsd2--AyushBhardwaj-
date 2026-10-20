package com.example.jwtrbac.repository;

import com.example.jwtrbac.model.Role;
import com.example.jwtrbac.model.User;
import jakarta.annotation.PostConstruct;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class UserRepository {

    private final Map<String, User> userByUsername = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder;

    public UserRepository(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initDefaultUsers() {
        // Default Admin User
        save(new User(
                UUID.randomUUID().toString(),
                "admin",
                passwordEncoder.encode("admin123"),
                "Administrator User",
                "admin@example.com",
                new HashSet<>(Arrays.asList(Role.ROLE_ADMIN, Role.ROLE_USER))
        ));

        // Default Normal User
        save(new User(
                UUID.randomUUID().toString(),
                "user",
                passwordEncoder.encode("user123"),
                "Standard User",
                "user@example.com",
                new HashSet<>(Collections.singletonList(Role.ROLE_USER))
        ));

        // Default Moderator User
        save(new User(
                UUID.randomUUID().toString(),
                "moderator",
                passwordEncoder.encode("mod123"),
                "Moderator User",
                "moderator@example.com",
                new HashSet<>(Collections.singletonList(Role.ROLE_MODERATOR))
        ));
    }

    public Optional<User> findByUsername(String username) {
        if (username == null) return Optional.empty();
        return Optional.ofNullable(userByUsername.get(username.toLowerCase()));
    }

    public boolean existsByUsername(String username) {
        if (username == null) return false;
        return userByUsername.containsKey(username.toLowerCase());
    }

    public boolean existsByEmail(String email) {
        if (email == null) return false;
        return userByUsername.values().stream()
                .anyMatch(u -> email.equalsIgnoreCase(u.getEmail()));
    }

    public User save(User user) {
        userByUsername.put(user.getUsername().toLowerCase(), user);
        return user;
    }

    public List<User> findAll() {
        return new ArrayList<>(userByUsername.values());
    }
}
