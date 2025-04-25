/**
 * Ubiquitous Language Summary:
 * Sub-entity of the AppUser aggregate. Encapsulates identity, credentials, roles, and status.
 * All lifecycle operations are restricted to the aggregate root (AppUser) via package-private access.
 */
package pl.kamann.domain.authuser;

import jakarta.persistence.AttributeOverride;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PrimaryKeyJoinColumn;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.Role;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
public class AuthUser implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Embedded
    @AttributeOverride(name = "value", column = @Column(name = "email"))
    private Email email;

    @Embedded
    @Column(nullable = false)
    private Password password;

    private boolean enabled;

    @ElementCollection(fetch = FetchType.EAGER)
    private final Set<Role> roles = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    private final Set<RefreshToken> refreshTokens = new HashSet<>();

    @Enumerated(EnumType.STRING)
    private AuthUserStatus status;

    @OneToOne(mappedBy = "authUser", cascade = CascadeType.ALL)
    @PrimaryKeyJoinColumn
    private AppUser appUser;

    protected AuthUser() {
    }

    public static AuthUser create(Email email, Password password, Set<Role> roles, AuthUserStatus status, AppUser appUser) {
        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Roles cannot be null or empty");
        }
        AuthUser user = new AuthUser(null, email, password, false, roles, null, status);
        user.appUser = appUser;
        return user;
    }

    public void activate() {
        this.status = AuthUserStatus.ACTIVE;
        this.enabled = true;
        // TODO: publish UserActivatedEvent
    }

    public void deactivate() {
        this.status = AuthUserStatus.INACTIVE;
        this.enabled = false;
        // TODO: publish UserDeactivatedEvent
    }

    public void changeStatus(AuthUserStatus newStatus) {
        this.status = Objects.requireNonNull(newStatus);
        this.enabled = (newStatus == AuthUserStatus.ACTIVE);
    }

    public void startDeletion() {
        this.status = AuthUserStatus.PENDING_DELETION;
    }

    public void finalizeDeletion() {
        this.status = AuthUserStatus.DELETED;
    }

    void addRole(Role role) {
        if (role == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }
        this.roles.add(role);
    }

    void removeRole(Role role) {
        this.roles.remove(role);
    }

    void addRefreshToken(RefreshToken token) {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        this.refreshTokens.add(token);
    }

    void revokeRefreshToken(RefreshToken token) {
        this.refreshTokens.remove(token);
    }

    public Long getId() {
        return id;
    }

    public Email getEmail() {
        return email;
    }

    public Password getPassword() {
        return password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Set<Role> getRoles() {
        return Set.copyOf(roles);
    }

    public Set<RefreshToken> getRefreshTokens() {
        return Set.copyOf(refreshTokens);
    }

    public AuthUserStatus getStatus() {
        return status;
    }

    public boolean hasRole(String role) {
        return roles.stream()
                .anyMatch(r -> r.getName().equalsIgnoreCase(role));
    }

    void linkAppUser(AppUser appUser) {
        this.appUser = appUser;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthUser authUser = (AuthUser) o;
        return Objects.equals(id, authUser.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    private AuthUser(Long id, Email email, Password password, boolean enabled, Set<Role> roles, Set<RefreshToken> refreshTokens, AuthUserStatus status) {
        this.id = id;
        this.email = Objects.requireNonNull(email, "Email cannot be null");
        this.password = Objects.requireNonNull(password, "Password cannot be null");
        this.enabled = enabled;
        if (roles != null) {
            this.roles.addAll(roles);
        }
        if (refreshTokens != null) {
            this.refreshTokens.addAll(refreshTokens);
        }
        this.status = Objects.requireNonNull(status, "Status cannot be null");
    }

    public void resetPassword(Password newPassword) {
        this.password = Objects.requireNonNull(newPassword, "New password cannot be null");
    }

    public static AuthUser create(Email email, Password password, Set<Role> roles) {
        AuthUser user = new AuthUser();
        user.email = email;
        user.password = password;
        user.status = AuthUserStatus.ACTIVE;
        user.enabled = true;
        if (roles != null) {
            user.roles.addAll(roles);
        }
        return user;
    }

}
