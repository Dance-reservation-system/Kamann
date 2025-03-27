package pl.kamann.config.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.repositories.AuthUserRepository;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final HandlerExceptionResolver exceptionResolver;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    public JwtAuthenticationFilter(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver) {
        this.exceptionResolver = exceptionResolver;
    }

    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    private static final List<String> PUBLIC_URLS = List.of(
            "/api/v1/auth/confirm",
            "/api/v1/auth/request-password-reset",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/register-client",
            "/api/v1/auth/register-instructor",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh-token",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        log.debug("JWT Filter Intercepted Request: {}", requestURI);

        if (isPublicUrl(requestURI)) {
            log.debug("Skipping JWT authentication for: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String token = jwtUtils.extractTokenFromRequest(request);
            jwtUtils.validateToken(token);

            log.debug("Extracted JWT Token: {}", token);

            String email = jwtUtils.extractEmail(token);
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

            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            exceptionResolver.resolveException(request, response, null, ex);
        }
    }

    private boolean isPublicUrl(String requestURI) {
        return PUBLIC_URLS.stream().anyMatch(pattern -> pathMatcher.match(pattern, requestURI));
    }
}