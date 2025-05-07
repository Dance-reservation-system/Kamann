package pl.kamann.domain.authuser.event;

import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.common.DomainEvent;

import java.time.Instant;

public record AuthUserRegistered(AuthUserId userId, Instant occurredOn)
    implements DomainEvent {
    public AuthUserRegistered {
        if (occurredOn == null) {
            throw new IllegalArgumentException("occurredOn cannot be null");
        }
    }
}