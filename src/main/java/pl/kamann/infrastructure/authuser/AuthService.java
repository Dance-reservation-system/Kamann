package pl.kamann.infrastructure.authuser;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.dto.AppUserResponseDto;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.RoleCodes;
import pl.kamann.domain.user.UserFactory;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.domain.appuser.RoleLookupService;
import pl.kamann.domain.appuser.UserLookupService;
import pl.kamann.domain.authuser.ValidationService;
import pl.kamann.infrastructure.security.jwt.JwtUtils;
import pl.kamann.domain.appuser.*;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.domain.authuser.RefreshToken;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.infrastructure.email.ConfirmUserService;
import pl.kamann.domain.authuser.RefreshTokenService;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    private final ConfirmUserService confirmUserService;
    private final UserFactory userFactory;
    private final AppUserMapper appUserMapper;

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;

    private final ValidationService validationService;
    private final UserLookupService userLookupService;
    private final RoleLookupService roleLookupService;
    private final RefreshTokenService refreshTokenService;

    private final ScheduledTaskService scheduledTaskService;

    public LoginResponse login(@Valid LoginRequest request, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            AuthUser authUser = (AuthUser) authentication.getPrincipal();

            if (authUser.getStatus() == AuthUserStatus.PENDING_DELETION) {
                scheduledTaskService.cancelTask(authUser.getEmail());
                authUser.setStatus(AuthUserStatus.ACTIVE);
            }
            log.info("User logged in successfully: email={}", authUser.getEmail());

            String accessToken = jwtUtils.generateToken(authUser.getEmail(), jwtUtils.createClaims("roles", authUser.getRoles().stream().map(Role::getName).toList()));
            String refreshToken = refreshTokenService.generateRefreshToken(authUser);

            response.addCookie(setCookie(refreshToken));
            return new LoginResponse(accessToken);
        } catch (DisabledException e) {
            log.warn("Attempted login with unconfirmed email: {}", request.email());
            throw new ApiException(
                    "Email not confirmed.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.EMAIL_NOT_CONFIRMED.name()
            );
        }
    }

    public LoginResponse refreshToken(String refreshToken, HttpServletResponse response) {
        log.info("Refreshing token: refreshToken={}", refreshToken);

        validationService.validateRefreshToken(refreshToken);

        RefreshToken token = refreshTokenService.getRefreshToken(refreshToken).orElseThrow(() ->
                new ApiException("Invalid refresh token",
                        HttpStatus.UNAUTHORIZED,
                        AuthCodes.INVALID_TOKEN.name()));

        validationService.isRefreshTokenExpired(token);

        AuthUser authUser = token.getAuthUser();

        String accessToken = jwtUtils.generateToken(authUser.getEmail(), jwtUtils.createClaims("roles", authUser.getRoles()));
        String newRefreshToken = refreshTokenService.generateRefreshToken(authUser);

        refreshTokenService.deleteRefreshToken(token);

        response.addCookie(unSetCookie());
        response.addCookie(setCookie(newRefreshToken));

        log.info("Token refreshed successfully: email={}", authUser.getEmail());

        return new LoginResponse(accessToken);
    }

    private Cookie createCookie(String refreshToken, int maxAge) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/api/v1/auth/refresh-token");
        cookie.setMaxAge(maxAge);
        return cookie;
    }

    private Cookie setCookie(String refreshToken) {
        return createCookie(refreshToken, 60 * 60 * 24);
    }

    private Cookie unSetCookie() {
        return createCookie("", 0);
    }

    @Transactional
    public AppUserDto registerClient(RegisterRequest request) {
        return registerUser(request, RoleCodes.CLIENT.name());
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return registerUser(request, RoleCodes.INSTRUCTOR.name());
    }

    private AppUserDto registerUser(RegisterRequest request, String roleCode) {
        validationService.validateEmailNotTaken(request.email());
        Role role = roleLookupService.findRoleByName(roleCode);

        AppUser appUser = userFactory.createAppUser(request);
        AuthUser authUser = userFactory.createAndLinkAuthWithApp(request, role, appUser);

        authUserRepository.save(authUser);
        AppUser savedAppUser = appUserRepository.save(appUser);

        confirmUserService.sendConfirmationEmail(authUser);

        log.info("User registered successfully: email={}, role={}", request.email(), role.getName());
        return appUserMapper.toAppUserDto(savedAppUser);
    }

    public AppUserResponseDto getLoggedInAppUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);

        AppUser appUser = userLookupService.findUserByEmail(email);
        return appUserMapper.toAppUserResponseDto(appUser);
    }

    public void requestAccountDeletion(String email) {
        log.info("Requesting account deletion for email: {}", email);

        AuthUser authUser = userLookupService.findUserByEmail(email).getAuthUser();

        authUser.setStatus(AuthUserStatus.PENDING_DELETION);

        scheduledTaskService.scheduledSoftDeletionUser(authUser);
        authUserRepository.save(authUser);
    }
}