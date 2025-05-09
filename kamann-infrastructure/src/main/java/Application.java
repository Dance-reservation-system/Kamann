import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(
        scanBasePackages = "pl.kamann", // ensures it scans `authuser.repository`
        exclude = {org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration.class} // optional if you need manual config
)
@EnableJpaRepositories(basePackages = "pl.kamann.authuser.repository")
@EntityScan(basePackages = "pl.kamann.domain")
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}