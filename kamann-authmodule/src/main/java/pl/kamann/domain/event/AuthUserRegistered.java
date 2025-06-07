package pl.kamann.domain.event;

import pl.kamann.domain.vo.AuthUserId;

import java.time.Instant;

public record AuthUserRegistered(AuthUserId userId, Instant occurredOn)
        implements DomainEvent {
    public AuthUserRegistered {
        if (occurredOn == null) {
            throw new IllegalArgumentException("occurredOn cannot be null");
        }
    }
}