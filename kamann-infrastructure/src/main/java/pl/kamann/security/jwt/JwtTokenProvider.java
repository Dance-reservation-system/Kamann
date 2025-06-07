package pl.kamann.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.TokenType;
import pl.kamann.domain.security.TokenProvider;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class JwtTokenProvider implements TokenProvider {

    private final JwtUtils jwtUtils;
    private final TokenClaimsFactory tokenClaimsFactory;

    @Override
    public String generateToken(AuthUser authUser) {
        Map<String, Object> claims = tokenClaimsFactory.createClaims(authUser);
        claims.put("type", TokenType.ACCESS.toString());
        return jwtUtils.generateToken(authUser.getEmail().value(), claims);
    }

    @Override
    public String generateTokenForType(Email email, TokenType tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType.toString());
        claims.put("email", email.value());
        return jwtUtils.generateToken(email.value(), claims);
    }

    @Override
    public boolean isValid(String token) {
        return jwtUtils.validateToken(token);
    }

    @Override
    public String generateVerificationLink(String baseUrl, String token) {
        return baseUrl + token;
    }

    @Override
    public String getSubject(String token) {
        return jwtUtils.getSubject(token);
    }
}
