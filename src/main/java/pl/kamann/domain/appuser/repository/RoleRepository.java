package pl.kamann.domain.appuser.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.domain.appuser.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String user);

}
