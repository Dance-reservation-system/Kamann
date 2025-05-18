package pl.kamann.infrastructure.security.jwt;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfiguration {

    @Bean
    public JwtUtils jwtUtils(JwtProperties properties) {
        return new JwtUtils(properties.getSecret(), properties.getExpiration());
    }
}