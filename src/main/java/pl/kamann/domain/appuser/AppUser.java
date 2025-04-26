/**
 * Ubiquitous Language Summary:
 * Aggregate root representing a domain user. Manages identity, personal details,
 * and delegates authentication-related transitions to encapsulate user lifecycle behavior.
 */
package pl.kamann.domain.appuser;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
public class AppUser implements Serializable {

    @Serial
    private static final long serialVersionUID = 1;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "auth_user_id", nullable = false)
    private AuthUser authUser;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    private String phone;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    protected AppUser() {
    }

    private AppUser(AppUserProfile profile, AuthUser authUser) {
        this.firstName = profile.firstName();
        this.lastName = profile.lastName();
        this.phone = profile.phone();
        this.authUser = Objects.requireNonNull(authUser, "AuthUser cannot be null");
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public static AppUser create(AppUserProfile profile, AuthUser authUser) {
        return new AppUser(profile, authUser);
    }

    public void changePhone(String newPhone) {
        if (newPhone != null && !newPhone.trim().isEmpty()) {
            this.phone = newPhone;
            this.updatedAt = LocalDateTime.now();
        }
    }

    public void activate() {
        this.authUser.activate();
    }

    public void deactivate() {
        this.authUser.deactivate();
    }

    public void finalizeAccountIfInactive() {
        if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
            authUser.deactivate();
            authUser.finalizeDeletion();
        }
    }

    public void changeStatus(AuthUserStatus status) {
        this.authUser.changeStatus(status);
    }

    public AuthUser getAuthUser() {
        return authUser;
    }

    public Long getId() {
        return id;
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

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void startDeletion() {
        this.authUser.startDeletion();
    }

    //todo used ONLY in data seeder
    public static AppUser create(String firstName, String lastName, AuthUser authUser) {
        AppUser user = new AppUser();
        user.firstName = firstName;
        user.lastName  = lastName;
        user.authUser  = authUser;
        user.createdAt = LocalDateTime.now();
        user.updatedAt = LocalDateTime.now();
        return user;
    }
}
