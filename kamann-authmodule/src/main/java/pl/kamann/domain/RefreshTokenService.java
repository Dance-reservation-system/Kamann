package pl.kamann.domain;

import pl.kamann.application.RefreshToken;

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