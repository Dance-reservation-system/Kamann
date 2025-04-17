package pl.kamann.infrastructure.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;

import java.util.Collection;
import java.util.stream.Collectors;

record AuthUserAdapter(AuthUser authUser) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authUser.getRoles().stream()
                .map(Role::getName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return authUser.getPassword();
    }

    @Override
    public String getUsername() {
        return authUser.getEmail();
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
}