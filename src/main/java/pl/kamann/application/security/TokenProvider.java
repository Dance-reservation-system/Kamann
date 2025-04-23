package pl.kamann.application.security;

import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.authuser.TokenType;

public interface TokenProvider {

    String generateToken(AuthUser authUser);

    boolean isValid(String token);

    String generateTokenForType(Email email, TokenType tokenType);

    String generateVerificationLink(String basePath, String token);
}