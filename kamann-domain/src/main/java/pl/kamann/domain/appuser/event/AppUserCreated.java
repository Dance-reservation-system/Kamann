package pl.kamann.domain.appuser.event;

import pl.kamann.domain.common.DomainEvent;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.vo.AuthUserId;

import java.time.Instant;

public record AppUserCreated(AppUserId appUserId,
                             AuthUserId authUserId,
                             Instant occurredOn)
    implements DomainEvent {
    public AppUserCreated {
        if (occurredOn == null) throw new IllegalArgumentException("occurredOn required");
    }
}