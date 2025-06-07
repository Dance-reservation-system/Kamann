package pl.kamann.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.authuser.RefreshTokenJpaRepository;
import pl.kamann.domain.authuser.entity.RefreshToken;
import pl.kamann.domain.authuser.port.out.RefreshTokenRepository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class JpaRefreshTokenRepositoryAdapter implements RefreshTokenRepository {

    private final RefreshTokenJpaRepository jpaRepository;
    private final RefreshTokenPersistenceMapper mapper;

    @Override
    public RefreshToken save(RefreshToken token) {
      return null;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return jpaRepository.findByToken(token)
            .map(entity -> mapper.toDomain(null, /* dummy or fetched AuthUser */ null));
    }

    @Override
    public void delete(RefreshToken token) {
        jpaRepository.deleteById(token.getId().value());
    }
}