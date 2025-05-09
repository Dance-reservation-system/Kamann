package pl.kamann.security.jwt;

import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.authuser.aggregate.AuthUser;

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
