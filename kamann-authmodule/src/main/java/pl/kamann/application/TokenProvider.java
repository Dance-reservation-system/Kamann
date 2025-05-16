package pl.kamann.application;

import pl.kamann.domain.AuthUser;
import pl.kamann.domain.Email;

public interface TokenProvider {

    String generateToken(AuthUser authUser);

    boolean isValid(String token);

    String generateTokenForType(Email email, TokenType tokenType);

    String generateVerificationLink(String basePath, String token);

    String getSubject(String token);
}