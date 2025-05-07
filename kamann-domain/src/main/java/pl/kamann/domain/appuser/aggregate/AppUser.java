package pl.kamann.domain.appuser.aggregate;

import pl.kamann.domain.appuser.event.AppUserProfileCreated;
import pl.kamann.domain.appuser.event.AppUserProfileUpdated;
import pl.kamann.domain.appuser.service.AppUserPolicy;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.common.AggregateRoot;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Aggregate root for application users.
 * Holds personal profile data and delegates authentication transitions
 * to the linked AuthUser.
 */
public class AppUser extends AggregateRoot<AppUserId> {

    private final AppUserId id;
    private final AuthUser authUser;
    private String firstName;
    private String lastName;
    private String phone;
    private final Instant createdAt;
    private Instant updatedAt;

    private AppUser(AppUserId id,
                    AuthUser authUser,
                    String firstName,
                    String lastName,
                    String phone) {
        super(id);
        this.id        = Objects.requireNonNull(id, "AppUserId required");
        this.authUser  = Objects.requireNonNull(authUser, "AuthUser required");
        this.firstName = Objects.requireNonNull(firstName, "First name required");
        this.lastName  = Objects.requireNonNull(lastName,  "Last name required");
        this.phone     = phone;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
        record(new AppUserProfileCreated(
                id,
                authUser.getId(),
                firstName,
                lastName,
                createdAt
        ));
    }

    public static AppUser create(AuthUser authUser,
                                 String firstName,
                                 String lastName,
                                 String phone,
                                 AppUserPolicy policy) {
        policy.ensureValidProfile(firstName, lastName, phone);
        return new AppUser(
                new AppUserId(UUID.randomUUID()),
                authUser,
                firstName,
                lastName,
                phone
        );
    }

    public void updateProfile(String firstName,
                              String lastName,
                              String phone,
                              AppUserPolicy policy) {
        policy.ensureValidProfile(firstName, lastName, phone);
        this.firstName = firstName;
        this.lastName  = lastName;
        this.phone     = phone;
        this.updatedAt = Instant.now();
        record(new AppUserProfileUpdated(
                id,
                firstName,
                lastName,
                updatedAt
        ));
    }

    @Override
    public AppUserId getId() {
        return id;
    }

    /**
     * @return the linked authentication user.
     */
    public AuthUser getAuthUser() {
        return authUser;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getPhone() {
        return phone;
    }

    /** @return when this profile was created */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /** @return when this profile was last updated */
    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void finalizeAccountIfInactive() {
        // todo implement
    }
}
