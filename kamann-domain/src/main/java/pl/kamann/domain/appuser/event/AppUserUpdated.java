package pl.kamann.domain.appuser.event;

import pl.kamann.domain.common.DomainEvent;
import pl.kamann.domain.appuser.vo.AppUserId;

import java.time.Instant;

public record AppUserUpdated(AppUserId appUserId,
                             Instant occurredOn)
    implements DomainEvent {
    public AppUserUpdated {
        if (occurredOn == null) throw new IllegalArgumentException("occurredOn required");
    }
}