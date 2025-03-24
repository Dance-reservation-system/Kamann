package pl.kamann.config.security;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        log.warn("Unauthorized access attempt to: {} {}", request.getMethod(), request.getRequestURI());

        if (authException.getCause() instanceof JwtException) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Token is expired");
        } else {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write(HttpStatus.UNAUTHORIZED.getReasonPhrase());
        }
    }
}
