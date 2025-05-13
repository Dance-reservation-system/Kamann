package pl.kamann.domain.authuser.port.out;

import pl.kamann.domain.authuser.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository {
    RefreshToken save(RefreshToken token);
    Optional<RefreshToken> findByToken(String token);
    void delete(RefreshToken token);
}