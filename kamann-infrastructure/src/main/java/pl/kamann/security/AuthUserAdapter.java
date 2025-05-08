package pl.kamann.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pl.kamann.domain.authuser.aggregate.AuthUser;

import java.io.Serial;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthUserAdapter implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    private final AuthUser authUser;

    public AuthUserAdapter(AuthUser authUser) {
        this.authUser = authUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<String> roleNames = authUser.getRoles().stream()
                .map(role -> "ROLE_" + role.getName())
                .collect(Collectors.toSet());
        return roleNames.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return authUser.getPassword().getValue();
    }

    @Override
    public String getUsername() {
        return authUser.getEmail().getValue();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return authUser.isEnabled();
    }

    public AuthUser getDomainUser() {
        return this.authUser;
    }
}