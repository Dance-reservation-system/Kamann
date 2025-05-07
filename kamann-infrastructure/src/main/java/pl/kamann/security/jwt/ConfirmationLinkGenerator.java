package pl.kamann.security.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.vo.TokenType;

@Service
@Getter
@RequiredArgsConstructor
public class ConfirmationLinkGenerator {

    @Value("${confirmation.link}")
    private String confirmationLink;

    @Value("${reset.password.link}")
    private String resetPasswordLink;

    private final JwtUtils jwtUtils;

    public String generateLink(String baseUrl, String token) {
        return baseUrl + token;
    }

    public String generateToken(String email, TokenType tokenType) {
        return jwtUtils.generateToken(email, jwtUtils.createClaims("TokenType", tokenType.toString()));
    }
}