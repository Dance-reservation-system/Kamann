package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.security.TokenProvider;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.RefreshToken;
import pl.kamann.domain.authuser.RefreshTokenService;
import pl.kamann.domain.authuser.dto.LoginResponse;
import pl.kamann.infrastructure.auth.cookie.RefreshTokenCookieFactory;
import pl.kamann.infrastructure.handler.ApiException;

@Service
@RequiredArgsConstructor
public class TokenRefreshFacade {

    private final RefreshTokenService refreshTokenService;
    private final TokenProvider tokenProvider;

    @Transactional
    public LoginResponse refreshAccessToken(String refreshToken, HttpServletResponse response) {
        RefreshToken token = refreshTokenService.getRefreshToken(refreshToken)
                .orElseThrow(() -> new ApiException("Invalid refresh token", HttpStatus.UNAUTHORIZED, AuthCodes.INVALID_TOKEN.name()));

        refreshTokenService.deleteRefreshToken(token);
        AuthUser authUser = token.getAuthUser();

        String accessToken = tokenProvider.generateToken(authUser);
        String newRefreshToken = refreshTokenService.generateRefreshToken(authUser);

        response.addCookie(RefreshTokenCookieFactory.create(newRefreshToken));

        return new LoginResponse(accessToken);
    }
}
