package pl.kamann.application;


import pl.kamann.domain.AuthUserId;

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
