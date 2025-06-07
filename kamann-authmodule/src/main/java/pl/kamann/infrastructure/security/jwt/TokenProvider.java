package pl.kamann.infrastructure.security.jwt;

import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.TokenType;

public interface TokenProvider {

    String generateToken(AuthUser authUser);

    boolean isValid(String token);

    String generateTokenForType(Email email, TokenType tokenType);

    String generateVerificationLink(String basePath, String token);

    String getSubject(String token);
}