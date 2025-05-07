package pl.kamann.application.auth;

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
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.exception.InvalidCredentialsException;
import pl.kamann.domain.authuser.service.RefreshTokenService;
import pl.kamann.domain.authuser.vo.AuthCode;
import pl.kamann.domain.authuser.vo.AuthUserStatus;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.authuser.validation.RefreshTokenValidator;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthLoginService {

    private static final int MAX_AGE = 7 * 24 * 3600; // 7 days

    //todo implement..
    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenValidator refreshTokenValidator;
    private final ScheduledTaskService scheduledTaskService;

    public LoginResponse login(@Valid LoginRequest request,
                               HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(), request.password()
                    )
            );
            AuthUser authUser = (AuthUser) authentication.getPrincipal();

            // If they had a pending-deletion scheduled, cancel it on login
            if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
                scheduledTaskService.cancelPendingDeletionTask(authUser.getEmail().getValue());
                authUser.activate();
            }

            log.info("User logged in successfully: email={}", authUser.getEmail());
            return issueTokensAndSetCookies(authUser, response);

        } catch (DisabledException e) {
            log.warn("Login attempt with unconfirmed email: {}", request.email());
            throw new ApiException(
                    "Email not confirmed.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCode.EMAIL_NOT_CONFIRMED.name()
            );
        } catch (InvalidCredentialsException e) {
            throw new ApiException(
                    "Invalid credentials.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCode.INVALID_CREDENTIALS.name()
            );
        }
    }

    public LoginResponse refreshToken(String refreshTokenValue,
                                      HttpServletResponse response) {
        log.info("Refreshing token: refreshToken={}", refreshTokenValue);

        // 1) Validate format / basic checks
        refreshTokenValidator.validateRefreshToken(refreshTokenValue);

        // 2) Lookup via domain port
        RefreshToken token = refreshTokenService
                .findByToken(refreshTokenValue)
                .orElseThrow(() ->
                        new ApiException(
                                "Invalid refresh token",
                                HttpStatus.UNAUTHORIZED,
                                AuthCode.INVALID_TOKEN.name()
                        )
                );

        // 3) Check expiry
        refreshTokenValidator.validateNotExpired(token);

        // 4) Revoke the old one
        refreshTokenService.revoke(token);

        AuthUser authUser = token.getAuthUser();

        // 5) Remove old cookie
        response.addCookie(unsetCookie());

        // 6) Issue new tokens
        return issueTokensAndSetCookies(authUser, response);
    }

    private LoginResponse issueTokensAndSetCookies(AuthUser authUser,
                                                   HttpServletResponse response) {
        // a) Create access token
        String accessToken = jwtUtils.generateToken(
                authUser.getEmail().value(),
                jwtUtils.createClaims(
                        "roles",
                        authUser.getRoles().stream()
                                .map(Role::name)
                                .collect(Collectors.toSet())
                )
        );

        // b) Issue & persist new refresh token via domain service
        RefreshToken newToken = refreshTokenService.issue(authUser);

        // c) Send cookie to client
        response.addCookie(setCookie(newToken.getToken()));

        return new LoginResponse(accessToken);
    }

    private static Cookie setCookie(String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(MAX_AGE);
        return cookie;
    }

    private static Cookie unsetCookie() {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        return cookie;
    }
}
