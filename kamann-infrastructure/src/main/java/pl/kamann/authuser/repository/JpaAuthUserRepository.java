package pl.kamann.authuser.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.domain.authuser.aggregate.AuthUser;

import java.util.Optional;

public interface JpaAuthUserRepository extends JpaRepository<AuthUser, Long> {
    Optional<AuthUser> findByEmail(String email);
}