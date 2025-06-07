package pl.kamann.appuser.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import pl.kamann.appuser.entity.AppUserEntity;

import java.util.Optional;

@Repository
public interface JpaAppUserRepository extends JpaRepository<AppUserEntity, Long> {
    Optional<AppUserEntity> findByAuthUserId(Long authUserId);
    Optional<AppUserEntity> findByEmail(String email);

    @Query("SELECT a FROM AppUserEntity a JOIN FETCH a.authUser WHERE a.id = :id")
    Optional<AppUserEntity> findByIdWithAuthUser(@Param("id") Long id);
}