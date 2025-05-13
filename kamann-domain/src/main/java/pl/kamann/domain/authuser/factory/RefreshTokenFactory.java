package pl.kamann.domain.authuser.factory;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.vo.RefreshTokenId;
import pl.kamann.domain.authuser.vo.TokenType;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

public class RefreshTokenFactory {
    private final Clock clock;

    public RefreshTokenFactory(Clock clock) {
        this.clock = clock;
    }

    /**
     * Creates a new RefreshToken for the given user, valid for 7 days.
     */
    public RefreshToken createFor(AuthUser authUser) {
        RefreshTokenId id  = new RefreshTokenId(1L);
        String tokenString = UUID.randomUUID().toString();
        Instant expiresAt  = Instant.now(clock).plusSeconds(7 * 24 * 3600);

        // ← pass authUser into the static factory
        return RefreshToken.of(
                id,
                authUser.getId(),
                tokenString,
                expiresAt,
                TokenType.REFRESH,
                authUser
        );
    }
}
