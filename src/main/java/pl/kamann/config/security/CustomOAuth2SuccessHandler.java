package pl.kamann.config.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import pl.kamann.config.exception.services.RoleLookupService;
import pl.kamann.config.exception.services.ValidationService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.LoginProvider;
import pl.kamann.entities.appuser.Role;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.ConfirmUserService;
import pl.kamann.services.RefreshTokenService;
import pl.kamann.services.factory.UserFactory;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final AuthUserRepository authUserRepository;
    private final RoleLookupService roleLookupService;
    private final RefreshTokenService refreshTokenService;
    private final UserFactory userFactory;
    private final ConfirmUserService confirmUserService;
    private final ValidationService validationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("User want to login with OAuth2");
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();
        LoginProvider loginProvider = LoginProvider.valueOf(oauthToken.getAuthorizedClientRegistrationId().toUpperCase());

        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");

        boolean isNewUser = authUserRepository.findByEmail(email).isEmpty();

        AuthUser authUser = isNewUser
                ? handleRegistration(request, email, firstName, lastName, loginProvider)
                : authUserRepository.findByEmail(email).get();

        if (!isNewUser) {
            handleLogin(authUser, loginProvider);
        }

        if (authUser.getStatus() == AuthUserStatus.ACTIVE) {
            Map<String, Object> claims = jwtUtils.createClaims("role", authUser.getRoles().stream().map(Role::getName).toList());
            String token = jwtUtils.generateToken(email, claims);
            String refreshToken = refreshTokenService.generateRefreshToken(authUser);

            Cookie cookie = new Cookie("refresh_token", refreshToken);
            cookie.setHttpOnly(true);
            cookie.setPath("/api/v1/auth/refresh-token");
            cookie.setMaxAge(60 * 60 * 24);
            response.addCookie(cookie);

            response.getWriter().write(token);
            log.info("User {} successfully {}", email, isNewUser ? "registered and logged in" : "logged in");
        } else {
            log.info("User {} has status {}, not returning token", email, authUser.getStatus());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Account is awaiting admin approval");
        }

//        response.sendRedirect("http://localhost:3000/"); // Redirect to frontend application

    }

    private AuthUser handleRegistration(HttpServletRequest request, String email, String firstName, String lastName, LoginProvider loginProvider) {
        log.info("Registering new user with email: {}", email);

        validationService.isSessionHasRole(request);

        Role role = roleLookupService.findRoleByName(request.getSession().getAttribute("role").toString());
        request.getSession().removeAttribute("role");

        boolean isClient = role.getName().equals("CLIENT");

        AuthUserStatus status = isClient ? AuthUserStatus.ACTIVE : AuthUserStatus.PENDING;

        AuthUser newUser = userFactory.createAuthUserWithOAuthAndLinkToAppUser(email, loginProvider, firstName, lastName, role, status, isClient);

        if (!isClient) {
            confirmUserService.sendConfirmationEmail(newUser);
        }

        return authUserRepository.save(newUser);
    }

    private void handleLogin(AuthUser authUser, LoginProvider loginProvider) {
        log.info("User exists, proceeding with login");

        if (!authUser.getLoginProviders().contains(loginProvider)) {
            authUser.getLoginProviders().add(loginProvider);
            authUserRepository.save(authUser);
        }
    }
}
