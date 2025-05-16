package pl.kamann.domain;


import pl.kamann.application.AggregateRoot;
import pl.kamann.application.AppUserId;
import pl.kamann.application.AppUserPolicy;
import pl.kamann.application.AppUserProfileCreated;
import pl.kamann.application.AppUserProfileUpdated;
import pl.kamann.application.AuthUserStatus;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

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
        this.id = Objects.requireNonNull(id);
        this.authUser = Objects.requireNonNull(authUser);
        this.firstName = Objects.requireNonNull(firstName);
        this.lastName = Objects.requireNonNull(lastName);
        this.phone = phone;
        this.createdAt = Instant.now();
        this.updatedAt = this.createdAt;
        record(new AppUserProfileCreated(id, authUser.getId(), firstName, lastName, createdAt));
    }

    public AppUser(AppUserId id, AuthUser authUser, String firstName,
                   String lastName, String phone, Instant createdAt, Instant updatedAt) {
        super(id);
        this.id = id;
        this.authUser = authUser;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phone = phone;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public static AppUser create(AuthUser authUser,
                                 String firstName,
                                 String lastName,
                                 String phone,
                                 AppUserPolicy policy) {
        policy.ensureValidProfile(firstName, lastName, phone);
        return new AppUser(new AppUserId(UUID.randomUUID()), authUser, firstName, lastName, phone);
    }


    public void updateProfile(String firstName,
                              String lastName,
                              String phone,
                              AppUserPolicy policy) {
        policy.ensureValidProfile(firstName, lastName, phone);
        this.firstName = firstName;
        this.lastName = lastName;
        this.phone = phone;
        this.updatedAt = Instant.now();
        record(new AppUserProfileUpdated(id, firstName, lastName, updatedAt));
    }

    @Override
    public AppUserId getId() {
        return id;
    }

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

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void finalizeAccountIfInactive() {
    }

    public void changeStatus(AuthUserStatus status) {
        this.authUser.changeStatus(status);
    }

    public void activate() {
        this.authUser.activate();
    }

    public void deactivate() {
        this.authUser.deactivate();
    }

    public AuthUserStatus getStatus() {
        return this.authUser.getStatus();
    }
}
