package pl.kamann.utility;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.test.context.ActiveProfiles;
import pl.kamann.config.security.jwt.JwtUtils;

@Configuration
@Profile("test")
public class TestSecurityConfig {

    @Bean
    @Primary
    public JwtUtils jwtUtils() {
        String testSecret = "daf66e01593f61a15b857cf433aae03a005812b31234e149036bcc8dee755dbb";  // Your hardcoded secret key
        JwtUtils jwtUtils = new JwtUtils();
        jwtUtils.setSecret(testSecret);
        jwtUtils.setExpiration(3600000L); // 1 hour expiration
        return jwtUtils;
    }
}