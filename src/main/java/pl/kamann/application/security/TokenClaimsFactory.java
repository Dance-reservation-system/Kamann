package pl.kamann.application.security;

import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;

import java.util.HashMap;
import java.util.Map;

@Component
public class TokenClaimsFactory {

    public Map<String, Object> createClaims(AuthUser authUser) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("email", authUser.getEmail().getValue());
        claims.put("userId", authUser.getId());
        claims.put("roles", authUser.getRoles().stream()
                .map(Role::getName)
                .toList());

        return claims;
    }
}
