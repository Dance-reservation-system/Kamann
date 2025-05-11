package pl.kamann.authuser.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.authuser.entity.AuthUserEntity;

import java.util.Optional;

public interface JpaAuthUserRepository extends JpaRepository<AuthUserEntity, Long> {
    Optional<AuthUserEntity> findByEmail(String email);
}