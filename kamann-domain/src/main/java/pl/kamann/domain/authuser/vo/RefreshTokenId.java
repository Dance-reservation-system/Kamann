package pl.kamann.domain.authuser.vo;

import java.util.Objects;
import java.util.UUID;

public record RefreshTokenId(UUID value) {
    public RefreshTokenId {
        Objects.requireNonNull(value, "id must not be null");
    }

    public static RefreshTokenId generate() {
        return new RefreshTokenId(UUID.randomUUID());
    }
}