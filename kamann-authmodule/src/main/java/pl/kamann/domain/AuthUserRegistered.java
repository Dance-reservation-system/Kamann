package pl.kamann.domain;

import pl.kamann.application.DomainEvent;

import java.time.Instant;

public record AuthUserRegistered(AuthUserId userId, Instant occurredOn)
        implements DomainEvent {
    public AuthUserRegistered {
        if (occurredOn == null) {
            throw new IllegalArgumentException("occurredOn cannot be null");
        }
    }
}