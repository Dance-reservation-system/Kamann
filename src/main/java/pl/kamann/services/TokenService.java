package pl.kamann.services;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.TokenType;

@Service
@Getter
@RequiredArgsConstructor
public class TokenService {
    @Value("${confirmation.link}")
    private String confirmationLink;

    @Value("${reset.password.link}")
    private String resetPasswordLink;

    private final JwtUtils jwtUtils;

    public String generateLink(String token, String link) {
        return link + token;
    }

    public String generateToken(String email, TokenType tokenType) {
        return jwtUtils.generateToken(email, jwtUtils.createClaims("TokenType", tokenType.toString()));
    }
}
