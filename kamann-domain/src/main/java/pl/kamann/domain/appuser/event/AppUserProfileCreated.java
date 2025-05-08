package pl.kamann.domain.appuser.event;

import pl.kamann.domain.common.DomainEvent;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.vo.AuthUserId;

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
