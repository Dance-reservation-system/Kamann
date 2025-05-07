package pl.kamann.domain.appuser.event;

import pl.kamann.domain.common.DomainEvent;
import pl.kamann.domain.appuser.vo.AppUserId;

import java.time.Instant;

/**
 * Raised when an AppUser profile is updated.
 */
public record AppUserProfileUpdated(
    AppUserId appUserId,
    String firstName,
    String lastName,
    Instant occurredOn
) implements DomainEvent {
    public AppUserProfileUpdated {
        if (occurredOn == null) throw new IllegalArgumentException("occurredOn required");
    }
}
