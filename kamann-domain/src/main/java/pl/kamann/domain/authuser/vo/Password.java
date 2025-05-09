package pl.kamann.domain.authuser.vo;

import pl.kamann.domain.authuser.service.PasswordHasher;

import java.util.Objects;

public record Password(String value) {
    public Password {
        Objects.requireNonNull(value, "password must not be null");
        String trimmed = value.trim();
        if (trimmed.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        value = trimmed;
    }

    @Override
    public String toString() {
        return "***";
    }

    public boolean matches(String rawPassword, PasswordHasher hasher) {
        return hasher.matches(rawPassword, this.value);
    }
}
