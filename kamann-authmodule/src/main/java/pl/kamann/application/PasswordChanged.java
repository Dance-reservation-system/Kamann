package pl.kamann.application;


import pl.kamann.domain.AuthUserId;

import java.time.Instant;

public record PasswordChanged(AuthUserId userId, Instant occurredOn)
    implements DomainEvent {
    public PasswordChanged {
        if (occurredOn == null) {
            throw new IllegalArgumentException("occurredOn cannot be null");
        }
    }
}