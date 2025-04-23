package pl.kamann.domain.authuser.validation;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.RefreshToken;
import pl.kamann.infrastructure.handler.ApiException;

import java.time.LocalDateTime;

@Component
public class RefreshTokenValidator {

    public void validateRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            throw new ApiException(
                    "Refresh token not provided",
                    HttpStatus.BAD_REQUEST,
                    AuthCodes.INVALID_TOKEN.name());
        }
    }

    public void validateNotExpired(RefreshToken token) {
        if (token.getExpirationTime().isBefore(LocalDateTime.now())) {
            throw new ApiException(
                    "Refresh token expired",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.INVALID_TOKEN.name());
        }
    }
}