package pl.kamann.domain.authuser;

import jakarta.persistence.Embeddable;
import pl.kamann.application.auth.PasswordHasher;

import java.util.Objects;

@Embeddable
public final class Password {

    public static final int MIN_PASSWORD_LENGTH = 8;

    private String value;

    private Password() {
    }

    public Password(String rawPassword, PasswordHasher hasher) {
        if (rawPassword == null || rawPassword.isBlank() || rawPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least 8 non-blank characters.");
        }
        this.value = hasher.encode(rawPassword);
    }

    public String getValue() {
        return value;
    }

    public boolean matches(String rawPassword, PasswordHasher hasher) {
        return hasher.matches(rawPassword, this.value);
    }

    @Override
    public String toString() {
        return "********";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Password that)) {
            return false;
        }
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
