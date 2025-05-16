package pl.kamann.application;



import pl.kamann.domain.AuthUserId;
import pl.kamann.domain.RefreshTokenId;

import java.time.Instant;
import java.util.Objects;

public record RefreshTokenIssued(
        RefreshTokenId id,
        AuthUserId userId,
        String token,
        Instant expiresAt,
        Instant occurredOn
) implements DomainEvent {
    public RefreshTokenIssued {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token cannot be null or blank");
        }
        Objects.requireNonNull(expiresAt,   "expiresAt cannot be null");
        Objects.requireNonNull(occurredOn,  "occurredOn cannot be null");
    }
}