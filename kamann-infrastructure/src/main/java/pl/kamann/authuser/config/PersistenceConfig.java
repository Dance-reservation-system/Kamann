package pl.kamann.authuser.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@Configuration
@EnableJpaRepositories(basePackages = "pl.kamann.authuser.repository")
@EntityScan(basePackages = "pl.kamann.authuser.entity")
public class PersistenceConfig {
}