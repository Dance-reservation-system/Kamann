package pl.kamann.security.jwt;

import org.springframework.stereotype.Component;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.Role;

import java.util.HashMap;
import java.util.Map;

@Component
public class TokenClaimsFactory {

    public Map<String, Object> createClaims(AuthUser authUser) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("email", authUser.getEmail().value());
        claims.put("userId", authUser.getId());
        claims.put("roles", authUser.getRoles().stream()
                .map(Role::name)
                .toList());

        return claims;
    }
}
