/**
 * Ubiquitous Language Summary:
 * Infrastructure-level implementation of TokenProvider.
 * Encapsulates JWT generation, validation, and claim encoding for AuthUser.
 */
package pl.kamann.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.security.TokenProvider;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.TokenType;
import pl.kamann.domain.security.TokenProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtTokenProvider implements pl.kamann.domain.security.TokenProvider {

    private final JwtUtils jwtUtils;

    @Override
    public String generateToken(AuthUser authUser) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authUser.getRoles().stream()
                .map(Role::name)
                .collect(Collectors.toSet()));
        claims.put("email", authUser.getEmail().value());
        claims.put("type", TokenType.ACCESS.toString());

        return jwtUtils.generateToken(authUser.getEmail().value(), claims);
    }

    @Override
    public boolean isValid(String token) {
        return jwtUtils.validateToken(token);
    }

    public String generateTokenForType(Email email, TokenType tokenType) {
        return jwtUtils.generateToken(
                email.value(),
                jwtUtils.createClaims("TokenType", tokenType.toString())
        );
    }

    public String generateVerificationLink(String baseUrl, String token) {
        return baseUrl + token;
    }
}