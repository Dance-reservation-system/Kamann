/**
 * Ubiquitous Language Summary:
 * Adapter that exposes AuthUser domain model to Spring Security framework.
 * Delegates identity and role-checking to domain AuthUser and encapsulates credentials.
 */
package pl.kamann.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.authuser.aggregate.AuthUser;

import java.io.Serial;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class SecurityUserDetails implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1;

    private final AuthUser authUser;

    public SecurityUserDetails(AuthUser authUser) {
        this.authUser = Objects.requireNonNull(authUser);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<Role> roles = authUser.getRoles();
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return authUser.getPassword().value();
    }

    @Override
    public String getUsername() {
        return authUser.getEmail().value();
    }

    @Override
    public boolean isEnabled() {
        return authUser.isEnabled();
    }

    public AuthUser getDomainUser() {
        return this.authUser;
    }
}
