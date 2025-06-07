package pl.kamann.domain.authuser.aggregate;

import pl.kamann.domain.authuser.event.RefreshTokenIssued;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.RefreshTokenId;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class RefreshToken {
    private final RefreshTokenId id;
    private final AuthUserId userId;
    private final String token;
    private final Instant expiresAt;
    private final List<Object> domainEvents = new ArrayList<>();

    private RefreshToken(RefreshTokenId id,
                         AuthUserId userId,
                         String token,
                         Instant expiresAt) {
        this.id        = Objects.requireNonNull(id);
        this.userId    = Objects.requireNonNull(userId);
        this.token     = Objects.requireNonNull(token);
        this.expiresAt = Objects.requireNonNull(expiresAt);
    }

    public static RefreshToken create(RefreshTokenId id,
                                      AuthUserId userId,
                                      String token,
                                      Instant expiresAt) {
        RefreshToken refreshToken = new RefreshToken(id, userId, token, expiresAt);
        refreshToken.domainEvents.add(new RefreshTokenIssued(id, userId, token, expiresAt, Instant.now()));
        return refreshToken;
    }

    public RefreshTokenId getId() {
        return id;
    }

    public AuthUserId getUserId() {
        return userId;
    }

    public String getToken() {
        return token;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public List<Object> pullDomainEvents() {
        List<Object> events = List.copyOf(domainEvents);
        domainEvents.clear();
        return events;
    }
}