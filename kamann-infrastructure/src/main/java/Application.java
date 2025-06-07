import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(
        scanBasePackages = "pl.kamann",
        exclude = {org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration.class}
)
@EnableJpaRepositories(basePackages = {
        "pl.kamann.authuser.repository",
        "pl.kamann.domain.authuser.entity" // <- dodaj to
})
@EntityScan(basePackages = "pl.kamann.domain")
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}