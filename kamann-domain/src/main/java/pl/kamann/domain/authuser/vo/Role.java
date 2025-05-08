package pl.kamann.domain.authuser.vo;

import java.util.Objects;

public record Role(String name) {
    public Role {
        Objects.requireNonNull(name, "role name must not be null");
        if (name.isBlank()) {
            throw new IllegalArgumentException("role name must not be blank");
        }
        name = name.trim();
    }

    public static final Role ADMIN      = new Role("ADMIN");
    public static final Role INSTRUCTOR = new Role("INSTRUCTOR");
    public static final Role CUSTOMER   = new Role("CUSTOMER");

    public static Role fromName(String roleName) {
        if (roleName == null) {
            throw new IllegalArgumentException("Role name must not be null");
        }

        return switch (roleName.trim().toUpperCase()) {
            case "ADMIN" -> Role.ADMIN;
            case "INSTRUCTOR" -> Role.INSTRUCTOR;
            case "CUSTOMER" -> Role.CUSTOMER;
            default -> throw new IllegalArgumentException("Unknown role: " + roleName);
        };
    }
}