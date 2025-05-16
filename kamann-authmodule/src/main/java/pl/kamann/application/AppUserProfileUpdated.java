package pl.kamann.application;


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
