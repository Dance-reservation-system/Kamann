package pl.kamann.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.RefreshToken;
import pl.kamann.repositories.RefreshTokenRepository;
import pl.kamann.testcontainers.config.TestContainersConfig;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {TestContainersConfig.class})
@ActiveProfiles("test")
public class RefreshTokenServiceTest {
    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    @Test
    public void shouldGenerateRefreshToken() {
        AuthUser authUser = new AuthUser();
        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setAuthUser(authUser);
        refreshToken.setToken(token);
        refreshToken.setExpirationTime(LocalDateTime.now().plusDays(1));

        when(refreshTokenRepository.save(any(RefreshToken.class))).thenReturn(refreshToken);

        String actualToken = refreshTokenService.generateRefreshToken(authUser);

        assertThat(actualToken).isNotNull();
        assertThat(actualToken).isEqualTo(token);
    }

    @Test
    public void shouldGetRefreshToken() {
        RefreshToken refreshToken = new RefreshToken();
        String token = UUID.randomUUID().toString();
        refreshToken.setToken(token);

        when(refreshTokenRepository.findByToken(token)).thenReturn(Optional.of(refreshToken));

        Optional<RefreshToken> actualRefreshToken = refreshTokenService.getRefreshToken(token);

        assertThat(actualRefreshToken).isPresent();
        assertThat(actualRefreshToken.get()).isEqualTo(refreshToken);
    }

    @Test
    public void shouldDeleteRefreshToken() {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshTokenService.deleteRefreshToken(refreshToken);

        verify(refreshTokenRepository, times(1)).delete(refreshToken);
    }

}
