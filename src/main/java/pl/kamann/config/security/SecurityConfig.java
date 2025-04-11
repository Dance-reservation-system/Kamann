package pl.kamann.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;
import pl.kamann.config.security.jwt.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final HandlerExceptionResolver exceptionResolver;
    private final CustomOAuth2SuccessHandler successHandler;

    @Autowired
    public SecurityConfig(@Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver, CustomOAuth2SuccessHandler successHandler) {
        this.exceptionResolver = exceptionResolver;
        this.successHandler = successHandler;
    }

    private static final String[] PUBLIC_URLS = {
            "/api/v1/auth/confirm",
            "/api/v1/auth/register-client",
            "/api/v1/auth/register-instructor",
            "/api/v1/auth/oauth2/register",
            "/api/v1/auth/login",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/oauth2/**",
            "/login/oauth2/**",
            "/favicon.ico"
    };

    private static final String[] ADMIN_URLS = {
            "/api/v1/admin/**",
            "/api/v1/admin/events/**"
    };

    private static final String[] CLIENT_URLS = {
            "/api/v1/client/**",
            "/api/v1/client/events/**",
            "/api/v1/client/attendance/**",
            "/api/v1/client/occurrences/**",
            "/api/v1/client/membership-cards/**"
    };

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(exceptionResolver);
    }

    @Bean
    @Profile(value = "prod")
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsSource) throws Exception {
        return getSecurityFilterChain(http, corsSource);
    }

    @Bean
    @Profile(value = "dev")
    public SecurityFilterChain securityFilterChainDevOriented(HttpSecurity http, CorsConfigurationSource corsSource) throws Exception {
        return getSecurityFilterChain(http, corsSource);
    }

    private SecurityFilterChain getSecurityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .requestMatchers(ADMIN_URLS).hasRole("ADMIN")
                        .requestMatchers(CLIENT_URLS).hasAnyRole("CLIENT", "ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(successHandler)
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler(new CustomAccessDeniedHandler())
                )
                .build();
    }
}