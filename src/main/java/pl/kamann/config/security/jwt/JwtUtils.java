package pl.kamann.config.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import pl.kamann.entities.appuser.TokenType;

import javax.crypto.SecretKey;
import java.util.*;

@Slf4j
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtUtils {

    @Setter
    private String secret;
    @Setter
    private long expiration;
    @Getter
    private SecretKey secretKey;

    public JwtUtils() {}

    @PostConstruct
    public void init() {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("Missing required property: jwt.secret");
        }
        this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        log.info("JWT Secret Key successfully initialized.");
    }

    public Map<String, Object> createClaims(String key, Object value) {
        return Collections.singletonMap(key, value);
    }

    public String generateToken(String email, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        return claimsResolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            log.error("JWT Parsing failed: {}", e.getMessage());
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    public boolean validateToken(String token, TokenType... expectedType) {
        try {
            Claims claims = extractAllClaims(token);

            if (expectedType.length > 0) {
                String tokenTypeString = claims.get("TokenType", String.class);
                if (!expectedType[0].name().equals(tokenTypeString)) {
                    log.warn("Token type mismatch: Expected {}, found {}", expectedType[0].name(), tokenTypeString);
                    return false;
                }
            }

            return !isTokenExpired(token);
        } catch (JwtException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public Optional<String> extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        return (bearerToken != null && bearerToken.startsWith("Bearer "))
                ? Optional.of(bearerToken.substring(7))
                : Optional.empty();
    }
}