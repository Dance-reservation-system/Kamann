package pl.kamann.infrastructure.persistence.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface JpaAuthUserRepository extends JpaRepository<AuthUserEntity, UUID> {
    @Query("SELECT u FROM AuthUserEntity u WHERE u.email = :email")
    Optional<AuthUserEntity> findByEmail(@Param("email") String email);
    List<AuthUserEntity> findByRolesContaining(String role);
}