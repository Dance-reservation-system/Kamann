package pl.kamann.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.entities.appuser.AppUser;

public interface AccountRepository extends JpaRepository<AppUser, Long> {
}
