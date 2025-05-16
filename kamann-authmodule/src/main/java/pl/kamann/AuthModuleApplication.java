package pl.kamann;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
        "pl.kamann.application",
        "pl.kamann.domain",
        "pl.kamann.infrastructure",
        "pl.kamann.security",
        "pl.kamann.web"
})
public class AuthModuleApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthModuleApplication.class, args);
    }
}