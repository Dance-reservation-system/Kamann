package pl.kamann.application;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class RefreshTokenValidator {

    public void validateRefreshToken(String token) {
        if (token == null || token.isBlank()) {
            throw new ApiException("Refresh token is blank",
                    HttpStatus.BAD_REQUEST,
                    AuthCode.INVALID_TOKEN.name());
        }
    }

    public void validateNotExpired(RefreshToken token) {
        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new ApiException("Refresh token has expired",
                    HttpStatus.BAD_REQUEST,
                    AuthCode.INVALID_TOKEN.name());
        }
    }
}