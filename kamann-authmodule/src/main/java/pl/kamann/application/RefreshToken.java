package pl.kamann.application;


import pl.kamann.domain.AuthUser;
import pl.kamann.domain.AuthUserId;
import pl.kamann.domain.RefreshTokenId;

import java.time.Instant;

/** A child-entity of AuthUser representing a refresh token. */
public class RefreshToken {
    private final RefreshTokenId id;
    private final AuthUserId userId;
    private final String token;
    private final Instant expiresAt;
    private final TokenType type;
    private final AuthUser authUser;

    private RefreshToken(RefreshTokenId id,
                         AuthUserId userId,
                         String token,
                         Instant expiresAt,
                         TokenType type,
                         AuthUser authUser) {
        this.id = id;
        this.userId = userId;
        this.token = token;
        this.expiresAt = expiresAt;
        this.type = type;
        this.authUser = authUser;
    }

    /** Static factory used by RefreshTokenFactory. */
    public static RefreshToken of(RefreshTokenId id,
                                  AuthUserId userId,
                                  String token,
                                  Instant expiresAt,
                                  TokenType type,
                                  AuthUser authUser) {
        return new RefreshToken(id, userId, token, expiresAt, type, authUser);
    }

    public RefreshTokenId getId()     {
        return id;
    }

    public AuthUserId getUserId() {
        return userId;
    }

    public String getToken()          {
        return token;
    }

    public Instant getExpiresAt()     {
        return expiresAt;
    }

    public TokenType getType()        {
        return type;
    }

    public AuthUser getAuthUser() {
        return authUser;
    }

    /** Helper to check expiration. */
    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }
}