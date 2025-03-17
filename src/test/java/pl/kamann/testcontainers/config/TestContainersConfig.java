package pl.kamann.testcontainers.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration
public class TestContainersConfig {
    private static final PostgreSQLContainer<?> POSTGRES_CONTAINER;

    static {
        System.out.println("Initializing PostgreSQL container for tests...");
        POSTGRES_CONTAINER = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16"))
                .withDatabaseName("testdb")
                .withUsername("test")
                .withPassword("test");

        // Start container
        POSTGRES_CONTAINER.start();

        // Log the JDBC URL for debugging
        System.out.println("PostgreSQL container started with URL: " + POSTGRES_CONTAINER.getJdbcUrl());
    }

    @DynamicPropertySource
    static void registerPgProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES_CONTAINER::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES_CONTAINER::getUsername);
        registry.add("spring.datasource.password", POSTGRES_CONTAINER::getPassword);
    }
}