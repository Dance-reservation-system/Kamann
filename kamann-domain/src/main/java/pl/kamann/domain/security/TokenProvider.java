package pl.kamann.domain.security;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.TokenType;

public interface TokenProvider {

    String generateToken(AuthUser authUser);

    boolean isValid(String token);

    String generateTokenForType(Email email, TokenType tokenType);

    String generateVerificationLink(String basePath, String token);
}