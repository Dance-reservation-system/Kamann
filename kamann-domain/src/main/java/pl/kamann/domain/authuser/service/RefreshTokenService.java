package pl.kamann.domain.authuser.service;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.entity.RefreshToken;

import java.util.Optional;

/**
 * Port for issuing, looking up and revoking refresh tokens.
 */
public interface RefreshTokenService {
    /**
     * Issue (create + persist) a new refresh token for the given user.
     */
    RefreshToken issue(AuthUser user);

    /**
     * Look up an existing token by its raw string.
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Revoke (delete) a previously issued token.
     */
    void revoke(RefreshToken token);
}