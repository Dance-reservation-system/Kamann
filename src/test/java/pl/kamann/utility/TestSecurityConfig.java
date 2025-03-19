package pl.kamann.utility;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import pl.kamann.config.security.jwt.JwtUtils;

import javax.crypto.SecretKey;
import java.util.Arrays;

@Configuration
@Profile("test")
public class TestSecurityConfig {
    
    @Bean
    @Primary
    public JwtUtils jwtUtils() {
        byte[] keyBytes = new byte[32];
        Arrays.fill(keyBytes, (byte) 1);
        SecretKey testKey = Keys.hmacShaKeyFor(keyBytes);
        
        return new JwtUtils(testKey, 3600000L); // 1 hour expiration for tests
    }
}