package pl.kamann.config.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AuthUserRepository;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final AuthUserRepository authUserRepository;
    private final String COOKIE_NAME = "refresh_token";

    private static final String API_BASE_PATH = "/api";
    private static final String API_VERSION = "/v1";
    private static final String AUTH_PATH = "/auth";
    private static final Set<String> EXCLUDED_URIS = Set.of(
            "/confirm",
            "/register-client",
            "/register-instructor",
            "/reset-password",
            "/request-password-reset",
            "/login"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        log.debug("JWT Filter Intercepted Request: {}", requestURI);

        String fullApiUrl = constructFullApiUrl(requestURI);
        log.debug("Constructed Full API URL: {}", fullApiUrl);

        if (shouldSkipAuthentication(requestURI)) {
            log.debug("Skipping JWT authentication for: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        Optional<String> tokenOpt = jwtUtils.extractTokenFromRequest(request);

        if (tokenOpt.isEmpty() || !jwtUtils.validateToken(tokenOpt.get())) {
            log.debug("No valid JWT token found. Skipping authentication.");
            filterChain.doFilter(request, response);
            return;
        }

        String token = tokenOpt.get();
        log.debug("Extracted JWT Token: {}", token);

        try {
            String email = jwtUtils.extractEmail(token);

            AuthUser user = authUserRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("User with email {} not found", email);
                        return new UsernameNotFoundException("User not found");
                    });

            // Check if the token is valid for the correct user
            if (!jwtUtils.isTokenFromUser(token, email)) {
                log.warn("Token does not belong to the current user.");
                throw new UsernameNotFoundException("Token does not belong to the user");
            }

            List<GrantedAuthority> authorities = user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Authenticated user: {}", email);

            // Create refresh token (this is a new step)
            String refreshToken = jwtUtils.generateTokenWithFlag(email, TokenType.REFRESH, 604800000L); // 7 days expiration

            // Create cookie and add httpOnly flag
            Cookie refreshTokenCookie = new Cookie(COOKIE_NAME, refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setPath("/");

            refreshTokenCookie.setSecure(request.isSecure());

            response.addCookie(refreshTokenCookie);

        } catch (UsernameNotFoundException ex) {
            log.error("Authentication failed: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        } catch (Exception ex) {
            log.error("An error occurred during authentication: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private boolean shouldSkipAuthentication(String requestURI) {
        String fullApiUrl = constructFullApiUrl(requestURI);
        return EXCLUDED_URIS.stream().anyMatch(fullApiUrl::endsWith);
    }

    private String constructFullApiUrl(String path) {
        return API_BASE_PATH + API_VERSION + AUTH_PATH + path;
    }
}