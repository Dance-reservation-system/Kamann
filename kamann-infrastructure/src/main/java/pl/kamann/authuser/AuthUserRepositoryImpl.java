package pl.kamann.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.authuser.entity.AuthUserEntity;
import pl.kamann.authuser.repository.JpaAuthUserRepository;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Role;
import shared.dto.PaginationCriteria;

import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class AuthUserRepositoryImpl implements AuthUserRepository {

    private final JpaAuthUserRepository jpaAuthUserRepository;
    private final AuthUserPersistenceMapper authUserPersistenceMapper;

    @Override
    public Optional<AuthUser> findByEmail(Email email) {
        Optional<AuthUserEntity> entity = jpaAuthUserRepository.findByEmail(email.value());
        return entity.map(authUserPersistenceMapper::toDomain);
    }

    @Override
    public void save(AuthUser user) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public void delete(AuthUser user) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public List<AuthUser> findByRole(Role admin) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public List<AuthUser> findAll(PaginationCriteria criteria) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public long count() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public List<AuthUser> findByRolesContaining(Role role, PaginationCriteria criteria) {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    @Override
    public long countByRole(Role role) {
        throw new UnsupportedOperationException("Not implemented yet");
    }
}
