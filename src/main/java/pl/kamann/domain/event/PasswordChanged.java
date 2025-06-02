package pl.kamann.domain.event;


import pl.kamann.domain.vo.AuthUserId;

import java.time.Instant;

public record PasswordChanged(AuthUserId userId, Instant occurredOn)
    implements DomainEvent {
    public PasswordChanged {
        if (occurredOn == null) {
            throw new IllegalArgumentException("occurredOn cannot be null");
        }
    }
}