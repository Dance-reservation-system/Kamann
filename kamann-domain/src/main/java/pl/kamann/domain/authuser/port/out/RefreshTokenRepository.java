package pl.kamann.domain.authuser.port.out;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.domain.authuser.entity.RefreshToken;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
}
