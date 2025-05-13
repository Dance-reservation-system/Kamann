package pl.kamann.domain.authuser;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.authuser.entity.RefreshTokenJpaEntity;

import java.util.Optional;

@Repository
public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenJpaEntity, Long> {
    Optional<RefreshTokenJpaEntity> findByToken(String token);
}