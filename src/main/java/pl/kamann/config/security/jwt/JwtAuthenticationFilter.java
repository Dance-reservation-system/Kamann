package pl.kamann.config.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import pl.kamann.repositories.AuthUserRepository;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final AuthUserRepository authUserRepository;

    private static final List<String> PUBLIC_URLS = List.of(
            "/api/v1/auth/confirm",
            "/api/v1/auth/register-client",
            "/api/v1/auth/register-instructor",
            "/api/v1/auth/request-password-reset",
            "/api/v1/auth/login"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        log.debug("JWT Filter Intercepted Request: {}", requestURI);

        if(isPublicUrl(request.getRequestURI())) {
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

        String email = jwtUtils.extractEmail(token);

        try {
            AuthUser user = authUserRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        log.warn("User with email {} not found", email);
                        return new UsernameNotFoundException("User not found");
                    });

            List<GrantedAuthority> authorities = user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                    .collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Authenticated user: {}", email);
        } catch (UsernameNotFoundException ex) {
            log.error("Authentication failed: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        } catch (Exception ex) {
            log.error("An error occurred during authentication: {}", ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicUrl(String requestURI) {
        return PUBLIC_URLS.stream().anyMatch(requestURI::startsWith);
    }
}