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
                .withPassword("test")
                .withReuse(true);

        // Start container
        POSTGRES_CONTAINER.start();
        if (POSTGRES_CONTAINER.isRunning()) {
            System.out.println("XXX PostgreSQL container started successfully.");
        } else {
            System.out.println("XXX Failed to start PostgreSQL container.");
        }

    }

    @DynamicPropertySource
    static void registerPgProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES_CONTAINER::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES_CONTAINER::getUsername);
        registry.add("spring.datasource.password", POSTGRES_CONTAINER::getPassword);
    }
}