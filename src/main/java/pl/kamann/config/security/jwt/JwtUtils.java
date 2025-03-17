package pl.kamann.config.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import pl.kamann.entities.appuser.Role;
import pl.kamann.entities.appuser.TokenType;

import javax.crypto.SecretKey;
import java.util.*;

@Slf4j
@Component
public class JwtUtils {

    @Getter
    private final SecretKey secretKey;
    private final long jwtExpiration;
    private final String COOKIE_NAME = "refresh_token";

    public JwtUtils(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration:36000000}") long jwtExpiration // default 10 hours
    ) {
        byte[] decodedKey = Base64.getDecoder().decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(decodedKey);
        this.jwtExpiration = jwtExpiration;
    }

    public String generateToken(String email, Set<Role> roles) {
        Map<String, Object> claims = createClaims("roles", roles.stream().map(Role::getName).toList());
        return generateTokenWithClaims(email, claims, jwtExpiration);
    }

    public String generateTokenWithFlag(String email, TokenType flag, long expirationTime) {
        Map<String, Object> claims = createClaims("TokenType", flag.toString());

        return generateTokenWithClaims(email, claims, expirationTime);
    }

    private Map<String, Object> createClaims(String key, Object value) {
        return Collections.singletonMap(key, value);
    }

    public String generateTokenWithClaims(String email, Map<String, Object> claims, long expiration) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        String token = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();

        log.info("Generated token for {}", email);

        return token;
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            log.error("Failed to extract claims from token: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            return !isTokenExpired(token);
        } catch (JwtException e) {
            log.error("JWT validation failed: {}", e.getMessage());
        }
        return false;
    }

    public boolean isTokenTypeValid(String token, TokenType expectedTokenType) {
        String tokenTypeString = extractClaim(token, claims -> claims.get("TokenType", String.class));

        TokenType tokenType = TokenType.valueOf(tokenTypeString);

        return tokenType.equals(expectedTokenType);
    }

    public boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }

    public boolean isTokenFromUser(String token, String userEmail) {
        String email = extractEmail(token);
        return email.equals(userEmail);
    }

    public boolean isValidRefreshToken(String token) {
        try {
            if (token == null || token.isEmpty()) {
                return false;
            }

            Claims claims = extractAllClaims(token);
            Date expirationDate = claims.getExpiration();
            return expirationDate != null && expirationDate.after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    private String extractTokenFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    public Optional<String> extractTokenFromRequest(HttpServletRequest request) {
        String token = extractTokenFromHeader(request);
        if (token != null) {
            return Optional.of(token);
        }

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }

        return Optional.empty();
    }
}