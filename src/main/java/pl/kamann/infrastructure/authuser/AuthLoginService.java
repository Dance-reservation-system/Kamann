package pl.kamann.infrastructure.authuser;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.RefreshToken;
import pl.kamann.domain.authuser.RefreshTokenService;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;
import pl.kamann.domain.authuser.validation.RefreshTokenValidator;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthLoginService {

    private static final Integer MAX_AGE = 604800;

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenValidator refreshTokenValidator;
    private final ScheduledTaskService scheduledTaskService;

    public LoginResponse login(@Valid LoginRequest request, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            AuthUser authUser = (AuthUser) authentication.getPrincipal();

            if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
                scheduledTaskService.cancelPendingDeletionTask(authUser.getEmail().getValue());
                authUser.activate();
            }

            log.info("User logged in successfully: email={}", authUser.getEmail());
            return generateTokensAndSetCookies(authUser, response);

        } catch (DisabledException e) {
            log.warn("Login attempt with unconfirmed email: {}", request.email());
            throw new ApiException("Email not confirmed.", HttpStatus.UNAUTHORIZED, AuthCodes.EMAIL_NOT_CONFIRMED.name());
        }
    }

    public LoginResponse refreshToken(String refreshToken, HttpServletResponse response) {
        log.info("Refreshing token: refreshToken={}", refreshToken);

        refreshTokenValidator.validateRefreshToken(refreshToken);

        RefreshToken token = refreshTokenService.getRefreshToken(refreshToken)
                .orElseThrow(() -> new ApiException("Invalid refresh token", HttpStatus.UNAUTHORIZED, AuthCodes.INVALID_TOKEN.name()));

        refreshTokenValidator.validateNotExpired(token);

        AuthUser authUser = token.getAuthUser();
        refreshTokenService.deleteRefreshToken(token);

        response.addCookie(unSetCookie());
        return generateTokensAndSetCookies(authUser, response);
    }

    private LoginResponse generateTokensAndSetCookies(AuthUser authUser, HttpServletResponse response) {
        String accessToken = jwtUtils.generateToken(
                authUser.getEmail().getValue(),
                jwtUtils.createClaims("roles", authUser.getRoles().stream().map(Role::getName).collect(Collectors.toSet()))
        );

        String refreshToken = refreshTokenService.generateRefreshToken(authUser);

        response.addCookie(setCookie(refreshToken));
        return new LoginResponse(accessToken);
    }

    private static Cookie setCookie(String refreshToken) {
        var cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(MAX_AGE);
        return cookie;
    }

    private static Cookie unSetCookie() {
        var cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}
