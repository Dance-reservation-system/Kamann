package pl.kamann.domain.common;

import java.util.Objects;
import java.util.UUID;

/**
 * Base class for all typed identifiers in your domain.
 * Subclasses simply call super(id).
 */
public abstract class Identifier {
    private final UUID value;

    protected Identifier(UUID value) {
        this.value = Objects.requireNonNull(value, "Identifier value cannot be null");
    }

    public UUID getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Identifier that = (Identifier) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}