package pl.kamann.infrastructure.persistence.jpa;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface JpaAppUserRepository extends JpaRepository<AppUserEntity, UUID> {

    Optional<AppUserEntity> findByAuthUser(AuthUserEntity authUser);

    Optional<AppUserEntity> findByAuthUser_Email(String email);

    @Query("SELECT a FROM AppUserEntity a JOIN FETCH a.authUser WHERE a.id = :id")
    Optional<AppUserEntity> findByIdWithAuth(@Param("id") UUID id);
}