package pl.kamann.infrastructure.security.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pl.kamann.domain.vo.TokenType;

import java.util.HashMap;
import java.util.Map;

@Service
@Getter
@RequiredArgsConstructor
public class ConfirmationLinkGenerator {

    @Value("${confirmation.link}")
    private String confirmationLink;

    @Value("${reset.password.link}")
    private String resetPasswordLink;

    private final TokenClaimsFactory tokenClaimsFactory;
    private final JwtUtils jwtUtils;

    public String generateLink(String baseUrl, String token) {
        return baseUrl + token;
    }

    public String generateToken(String email, TokenType tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", tokenType.toString());
        claims.put("email", email);
        return jwtUtils.generateToken(email, claims);
    }
}
