package pl.kamann.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(scanBasePackages = "pl.kamann")
@EnableCaching
@EnableScheduling
@EnableJpaRepositories(basePackages = {
		"pl.kamann.appuser.repository",
		"pl.kamann.domain.authuser"
})
@EntityScan(basePackages = {
		"pl.kamann.appuser.entity",
		"pl.kamann.domain.authuser.entity",
		"pl.kamann.authuser"
})
public class Application {
	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
}