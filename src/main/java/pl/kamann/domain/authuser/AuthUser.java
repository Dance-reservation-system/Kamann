package pl.kamann.domain.authuser;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import pl.kamann.domain.appuser.Role;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
public class AuthUser implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    private boolean enabled;

    @ElementCollection(fetch = FetchType.EAGER)
    private final Set<Role> roles = new HashSet<>();

    @OneToMany(cascade = CascadeType.ALL, orphanRemoval = true)
    private final Set<RefreshToken> refreshTokens = new HashSet<>();

    @Enumerated(EnumType.STRING)
    private AuthUserStatus status;

    private AuthUser(Long id, String email, String password, boolean enabled, Set<Role> roles, Set<RefreshToken> refreshTokens, AuthUserStatus status) {
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

    public static AuthUser create(String email, String password, Set<Role> roles, AuthUserStatus status) {
        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Roles cannot be null or empty");
        }
        return new AuthUser(null, email, password, false, roles, null, status);
    }

    public void activate() {
        this.status = AuthUserStatus.ACTIVE;
        this.enabled = true;
        // Publish domain event
    }

    public void deactivate() {
        this.status = AuthUserStatus.INACTIVE;
        this.enabled = false;
        // Publish domain event
    }

    public void addRole(Role role) {
        if (role == null) {
            throw new IllegalArgumentException("Role cannot be null");
        }
        this.roles.add(role);
    }

    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    public void addRefreshToken(RefreshToken token) {
        if (token == null) {
            throw new IllegalArgumentException("Token cannot be null");
        }
        this.refreshTokens.add(token);
    }

    public void revokeRefreshToken(RefreshToken token) {
        this.refreshTokens.remove(token);
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public Set<RefreshToken> getRefreshTokens() {
        return Collections.unmodifiableSet(refreshTokens);
    }

    public AuthUserStatus getStatus() {
        return status;
    }

    public boolean hasRole(String role) {
        return roles.stream()
                .anyMatch(r -> r.getName().equalsIgnoreCase(role));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthUser authUser = (AuthUser) o;
        return Objects.equals(id, authUser.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}