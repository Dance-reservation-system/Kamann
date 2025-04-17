package pl.kamann.domain.appuser;

import jakarta.persistence.Embeddable;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

@Embeddable
public class Role implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String name;

    private Role() {
        this.name = null;
    }

    private Role(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name cannot be null or empty");
        }
        this.name = name;
    }

    public static Role of(String name) {
        return new Role(name);
    }

    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Role role = (Role) o;
        return Objects.equals(name, role.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    public static final Role ADMIN = new Role("ADMIN");
    public static final Role INSTRUCTOR = new Role("INSTRUCTOR");
    public static final Role USER = new Role("USER");
}