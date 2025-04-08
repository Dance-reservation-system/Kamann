package pl.kamann.config.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import pl.kamann.config.exception.services.RoleLookupService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.LoginProvider;
import pl.kamann.entities.appuser.Role;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.RefreshTokenService;
import pl.kamann.services.factory.UserFactory;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final AuthUserRepository authUserRepository;
    private final RoleLookupService roleLookupService;
    private final RefreshTokenService refreshTokenService;
    private final UserFactory userFactory;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User user = oauthToken.getPrincipal();
        LoginProvider loginProvider = LoginProvider.valueOf(oauthToken.getAuthorizedClientRegistrationId().toUpperCase());

        String email = user.getAttribute("email");
        String firstName = user.getAttribute("given_name");
        String lastName = user.getAttribute("family_name");

        Role clientRole = roleLookupService.findRoleByName("CLIENT");

        AuthUser authUser = authUserRepository.findByEmail(email)
                .orElseGet(() -> authUserRepository.save(
                        userFactory.createAuthUserWithOAuthAndLinkToAppUser(email, loginProvider, firstName, lastName, clientRole)
                ));

        if (!authUser.getLoginProviders().contains(loginProvider)) {
            authUser.getLoginProviders().add(loginProvider);
            authUserRepository.save(authUser);
        }

        Map<String, Object> claims = jwtUtils.createClaims("role", "CLIENT");
        String token = jwtUtils.generateToken(email, claims);

        String refreshToken = refreshTokenService.generateRefreshToken(authUser);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/api/v1/auth/refresh-token");
        cookie.setMaxAge(60 * 60 * 24);
        response.addCookie(cookie);

        System.out.println();

        response.getWriter().write(token);

//        response.sendRedirect("http://localhost:3000/"); // Redirect to frontend application

    }
}
