package pl.kamann.services;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.codes.RoleCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.services.RoleLookupService;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.config.exception.services.ValidationService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.dtos.AppUserDto;
import pl.kamann.dtos.AppUserResponseDto;
import pl.kamann.dtos.login.LoginRequest;
import pl.kamann.dtos.login.LoginResponse;
import pl.kamann.dtos.register.RegisterRequest;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.RefreshToken;
import pl.kamann.entities.appuser.Role;
import pl.kamann.mappers.AppUserMapper;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.factory.UserFactory;

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

    public LoginResponse login(@Valid LoginRequest request, HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            AuthUser authUser = (AuthUser) authentication.getPrincipal();
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
        } catch (BadCredentialsException e) {
            log.warn("Invalid User credentials attempt for email: {}", request.email());
            throw new ApiException(
                    "Invalid user credentials.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.UNAUTHORIZED.name()
            );
        }
    }


    public LoginResponse refreshToken(String refreshToken, HttpServletResponse response) {
        log.info("Refreshing token: refreshToken={}", refreshToken);
        response.addCookie(unSetCookie());
        validationService.validateRefreshToken(refreshToken);

        RefreshToken token = refreshTokenService.getRefreshToken(refreshToken).orElseThrow(() ->
                new ApiException("Invalid refresh token",
                        HttpStatus.UNAUTHORIZED,
                        AuthCodes.INVALID_TOKEN.name()));

        refreshTokenService.deleteRefreshToken(token);
        validationService.isRefreshTokenExpired(token);

        AuthUser authUser = token.getAuthUser();
        authUserRepository.save(authUser);
        String accessToken = jwtUtils.generateToken(authUser.getEmail(), jwtUtils.createClaims("roles", authUser.getRoles()));
        String newRefreshToken = refreshTokenService.generateRefreshToken(authUser);

        log.info("Token refreshed successfully: email={}", authUser.getEmail());

        response.addCookie(setCookie(newRefreshToken));
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
        String token = jwtUtils.extractTokenFromRequest(request)
                .orElseThrow(() -> new ApiException("Invalid or missing token",
                        HttpStatus.UNAUTHORIZED,
                        AuthCodes.INVALID_TOKEN.name()));

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);

        AppUser appUser = userLookupService.findUserByEmail(email);
        return appUserMapper.toAppUserResponseDto(appUser);
    }
}