package pl.kamann.config.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import pl.kamann.entities.appuser.TokenType;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

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

    public JwtUtils() {
    }

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
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
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
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(null, null, e.getMessage());
        } catch (SignatureException e) {
            throw new SignatureException(e.getMessage());
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException(e.getMessage());
        }
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
            throw new IllegalArgumentException("No JWT token found in request");
        }

        return bearerToken.substring(7);
    }
}