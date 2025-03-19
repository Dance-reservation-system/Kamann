package pl.kamann.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.RefreshToken;
import pl.kamann.repositories.RefreshTokenRepository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public String generateRefreshToken(AuthUser authUser) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setAuthUser(authUser);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpirationTime(LocalDateTime.now().plusDays(1));

        refreshToken = refreshTokenRepository.save(refreshToken);

        return refreshToken.getToken();
    }

    Optional<RefreshToken> getRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    void deleteRefreshToken(RefreshToken token) {
        refreshTokenRepository.delete(token);
    }
}
