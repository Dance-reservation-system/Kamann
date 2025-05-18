package pl.kamann.domain.event;


import pl.kamann.domain.vo.AuthUserId;
import pl.kamann.domain.vo.AppUserId;

import java.time.Instant;

/**
 * Raised when an AppUser profile is first created.
 */
public record AppUserProfileCreated(
    AppUserId appUserId,
    AuthUserId authUserId,
    String firstName,
    String lastName,
    Instant occurredOn
) implements DomainEvent {
    public AppUserProfileCreated {
        if (occurredOn == null) throw new IllegalArgumentException("occurredOn required");
    }
}
