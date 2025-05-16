package pl.kamann.application;

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
import pl.kamann.domain.AppUser;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.InvalidCredentialsException;
import pl.kamann.domain.RefreshTokenService;
import pl.kamann.infrastructure.ScheduledTaskService;
import pl.kamann.security.jwt.TokenClaimsFactory;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthLoginService {

    private static final int MAX_AGE = 7 * 24 * 3600; // 7 days

    private final TokenProvider tokenProvider;
    private final TokenClaimsFactory tokenClaimsFactory;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenValidator refreshTokenValidator;
    private final ScheduledTaskService scheduledTaskService;
    private final AppUserFinder appUserFinder;

    public LoginResponse login(@Valid LoginRequest request,
                               HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email(), request.password()
                    )
            );
            AuthUser authUser = (AuthUser) authentication.getPrincipal();

            if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
                scheduledTaskService.cancelPendingDeletionTask(authUser.getEmail().value());
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

        refreshTokenValidator.validateRefreshToken(refreshTokenValue);

        RefreshToken token = refreshTokenService
                .findByToken(refreshTokenValue)
                .orElseThrow(() ->
                        new ApiException(
                                "Invalid refresh token",
                                HttpStatus.UNAUTHORIZED,
                                AuthCode.INVALID_TOKEN.name()
                        )
                );

        refreshTokenValidator.validateNotExpired(token);

        refreshTokenService.revoke(token);

        AuthUser authUser = token.getAuthUser();

        response.addCookie(unsetCookie());

        return issueTokensAndSetCookies(authUser, response);
    }

    private LoginResponse issueTokensAndSetCookies(AuthUser authUser,
                                                   HttpServletResponse response) {
        Map<String, Object> claims = tokenClaimsFactory.createClaims(authUser);
        String accessToken = tokenProvider.generateToken(authUser);

        RefreshToken newToken = refreshTokenService.issue(authUser);
        response.addCookie(setCookie(newToken.getToken()));

        AppUser appUser = appUserFinder.findByAuthUser(authUser)
                .orElseThrow(() -> new RuntimeException("AppUser not found for auth user: " + authUser.getId()));

        String fullName = appUser.getFirstName() + " " + appUser.getLastName();
        String email = authUser.getEmail().value();

        return new LoginResponse(accessToken, email, fullName);
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
