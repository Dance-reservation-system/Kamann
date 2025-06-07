package pl.kamann.domain.authuser.aggregate;

import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.event.AuthUserRegistered;
import pl.kamann.domain.authuser.event.PasswordChanged;
import pl.kamann.domain.authuser.event.RefreshTokenIssued;
import pl.kamann.domain.authuser.factory.RefreshTokenFactory;
import pl.kamann.domain.authuser.service.AuthUserPolicy;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.AuthUserStatus;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Password;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.common.AggregateRoot;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Aggregate root for authentication users.
 */
public class AuthUser extends AggregateRoot<AuthUserId> {
    private final AuthUserId id;
    private final Email email;
    private Password password;
    private AuthUserStatus status;
    private final Set<Role> roles = new HashSet<>();
    private final Set<RefreshToken> refreshTokens = new HashSet<>();

    public AuthUser(AuthUserId authUserId, AuthUserId id, Email email) {
        super(authUserId);
        this.id = id;
        this.email = email;
    }

    // Private constructor enforces invariants and records registration event
    private AuthUser(AuthUserId id,
                     Email email,
                     Password password,
                     Set<Role> roles) {
        super(id);
        this.id = id;
        this.email = email;
        this.password = password;
        this.roles.addAll(roles);
        this.status = AuthUserStatus.ACTIVE;
        record(new AuthUserRegistered(id, Instant.now()));
    }

    /**
     * Factory method for registering a new user.
     */
    public static AuthUser register(Email email,
                                    Password password,
                                    Set<Role> roles,
                                    AuthUserPolicy policy) {
        policy.ensureEmailNotTaken(email);
        return new AuthUser(
            null,
                email,
                password,
                roles
        );
    }

    /**
     * Change this user's password.
     */
    public void changePassword(Password newPassword, AuthUserPolicy policy) {
        policy.ensureCanChangePassword(this);
        this.password = newPassword;
        record(new PasswordChanged(id, Instant.now()));
    }

    /**
     * Issue a new refresh token for this user.
     */
    public RefreshToken issueRefreshToken(RefreshTokenFactory factory) {
        RefreshToken token = factory.createFor(this);
        this.refreshTokens.add(token);
        record(new RefreshTokenIssued(
                token.getId(),
                this.id,
                token.getToken(),
                token.getExpiresAt(),
                Instant.now()
        ));
        return token;
    }

    /**
     * Revoke (remove) a previously issued refresh token.
     */
    public void revokeRefreshToken(RefreshToken token) {
        this.refreshTokens.remove(token);
    }

    /**
     * Activate this user (e.g. after email confirmation).
     */
    public void activate() {
        this.status = AuthUserStatus.ACTIVE;
    }

    /**
     * @return true if this user is currently active/enabled.
     */
    public boolean isEnabled() {
        return this.status == AuthUserStatus.ACTIVE;
    }

    // Read-only accessors

    @Override
    public AuthUserId getId() {
        return id;
    }

    public Email getEmail() {
        return email;
    }

    /**
     * Add this getter so your authentication layer can read the hashed password.
     */
    public Password getPassword() {
        return password;
    }

    public Set<Role> getRoles() {
        return Set.copyOf(roles);
    }

    public AuthUserStatus getStatus() {
        return status;
    }

    public boolean isActive() {
        return this.status == AuthUserStatus.ACTIVE;
    }

    public Set<RefreshToken> getRefreshTokens() {
        return Set.copyOf(refreshTokens);
    }

    public void resetPassword(Password newPassword) {
        this.password = newPassword;
    }

    public void deactivate() {
        this.status = AuthUserStatus.INACTIVE;
    }

    public void changeStatus(AuthUserStatus status) {
        if (status == null) {
            throw new IllegalArgumentException("Status cannot be null");
        }
        this.status = status;
    }

    public void startDeletion() {
        this.status = AuthUserStatus.PENDING_DELETION;
    }

    public static AuthUser restore(AuthUserId id,
                                   Email email,
                                   Password password,
                                   Set<Role> roles,
                                   AuthUserStatus status) {
        AuthUser user = new AuthUser(id, email, password, roles);
        user.status = status;
        return user;
    }
}
