package pl.kamann.infrastructure.security;

import pl.kamann.domain.appuser.Role;

import java.util.Objects;
import java.util.Set;

public record RawAuthUserInput(String email, String password, Set<Role> roles) {

    public RawAuthUserInput {
        Objects.requireNonNull(email, "Email is required");
        Objects.requireNonNull(password, "Password is required");
        Objects.requireNonNull(roles, "Roles are required");

        if (email.isBlank()) {
            throw new IllegalArgumentException("Email cannot be blank");
        }
        if (password.isBlank()) {
            throw new IllegalArgumentException("Password cannot be blank");
        }
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("At least one role is required");
        }
    }
}