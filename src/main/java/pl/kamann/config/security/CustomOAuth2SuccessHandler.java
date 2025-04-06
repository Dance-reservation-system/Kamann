package pl.kamann.config.security;

import jakarta.servlet.ServletException;
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
import pl.kamann.entities.appuser.*;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.RefreshTokenService;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final AuthUserRepository authUserRepository;
    private final RoleLookupService roleLookupService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User user = oauthToken.getPrincipal();

        String email = user.getAttribute("email");
        String firstName = user.getAttribute("given_name");
        String lastName = user.getAttribute("family_name");

        Role clientRole = roleLookupService.findRoleByName("CLIENT");

        AuthUser authUser = authUserRepository.findByEmail(email)
                .orElseGet(() -> {
                    AppUser appUser = AppUser.builder()
                            .firstName(firstName)
                            .lastName(lastName)
                            .createdAt(LocalDateTime.now())
                            .build();

                    AuthUser newauthUser = AuthUser.builder()
                            .email(email)
                            .loginProvider(LoginProvider.GOOGLE)
                            .roles(Set.of(clientRole))
                            .status(AuthUserStatus.ACTIVE)
                            .enabled(true)
                            .build();

                    newauthUser.setAppUser(appUser);
                    appUser.setAuthUser(newauthUser);

                    return authUserRepository.save(newauthUser);
                });


        if(authUser.getLoginProvider().equals(LoginProvider.LOCAL)) {
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write("Must use local login, or add Google login to your account");
            return;
        }

        Map<String, Object> claims = jwtUtils.createClaims("role", "CLIENT");
        String token = jwtUtils.generateToken(email, claims);

        String refreshToken = refreshTokenService.generateRefreshToken(authUser);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/api/v1/auth/refresh-token");
        cookie.setMaxAge(60 * 60 * 24);
        response.addCookie(cookie);

        response.getWriter().write(token);

//        response.sendRedirect("http://localhost:3000/"); // Redirect to your frontend application
    }
}
