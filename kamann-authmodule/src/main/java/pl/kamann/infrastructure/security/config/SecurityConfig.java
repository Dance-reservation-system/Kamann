package pl.kamann.infrastructure.security.config;


import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerExceptionResolver;
import pl.kamann.infrastructure.security.handler.CustomAccessDeniedHandler;
import pl.kamann.infrastructure.security.jwt.JwtAuthenticationFilter;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

import java.util.List;

@Configuration
@EnableWebSecurity
class SecurityConfig {

    private final HandlerExceptionResolver exceptionResolver;

    public SecurityConfig(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.exceptionResolver = exceptionResolver;
    }

    private static final String[] PUBLIC_URLS = {
            "/api/v1/auth/confirm",
            "/api/v1/auth/request-password-reset",
            "/api/v1/auth/reset-password",
            "/api/v1/auth/register-customer",
            "/api/v1/auth/register-instructor",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh-token",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
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
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        return new JwtAuthenticationFilter(jwtUtils, userDetailsService);
    }

    @Bean
    @Profile("prod")
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) throws Exception {
        return getSecurityFilterChain(http, corsConfigurationSourceProd(), jwtAuthenticationFilter);
    }

    @Bean
    @Profile("dev")
    public SecurityFilterChain securityFilterChainDevOriented(
            HttpSecurity http,
            CorsConfigurationSource source,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) throws Exception {
        return getSecurityFilterChain(http, corsConfigurationSourceDev(), jwtAuthenticationFilter);
    }

    private SecurityFilterChain getSecurityFilterChain(
            HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_URLS).permitAll()
                        .requestMatchers(ADMIN_URLS).hasRole("ADMIN")
                        .requestMatchers(CLIENT_URLS).hasAnyRole("CLIENT", "ADMIN")
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler(new CustomAccessDeniedHandler())
                )
                .build();
    }

    @Bean
    @Profile("dev")
    @Primary
    public CorsConfigurationSource corsConfigurationSourceDev() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of(
                "http://localhost:3000"
        ));
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Profile("prod")
    public CorsConfigurationSource corsConfigurationSourceProd() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of(
                "https://kamann-production.up.railway.app"
        ));
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    @Profile("dev")
    public OpenAPI customOpenAPIDev() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("bearer-jwt",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter JWT token")
                        ))
                .info(new Info()
                        .title("Dance dance")
                        .version("1.0.0")
                        .description("API Documentation"))
                .addSecurityItem(new SecurityRequirement().addList("bearer-jwt"))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("API Server (Dev)")
                ));
    }

    @Bean
    @Profile("prod")
    public OpenAPI customOpenAPIProd() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("bearer-jwt",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Enter JWT token")
                        ))
                .info(new Info()
                        .title("Dance dance")
                        .version("1.0.0")
                        .description("API Documentation"))
                .addSecurityItem(new SecurityRequirement().addList("bearer-jwt"))
                .servers(List.of(
                        new Server().url("https://kamann-production.up.railway.app").description("API Server (Prod)")
                ));
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}