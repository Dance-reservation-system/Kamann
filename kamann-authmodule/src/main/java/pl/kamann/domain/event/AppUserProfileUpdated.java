package pl.kamann.domain.event;


import pl.kamann.domain.vo.AppUserId;

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
