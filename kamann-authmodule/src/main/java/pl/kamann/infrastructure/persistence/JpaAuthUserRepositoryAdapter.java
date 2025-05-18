package pl.kamann.infrastructure.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.infrastructure.persistence.jpa.JpaAuthUserRepository;
import pl.kamann.infrastructure.persistence.jpa.AuthUserEntity;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.Role;
import pl.kamann.infrastructure.persistence.mapper.AuthUserPersistenceMapper;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class JpaAuthUserRepositoryAdapter implements AuthUserRepository {

    private final JpaAuthUserRepository jpa;
    private final AuthUserPersistenceMapper mapper;

    @Override
    public Optional<AuthUser> findByEmail(Email email) {
        return jpa.findByEmail(email.value())
                .map(mapper::toDomain);
    }

    @Override
    public List<AuthUser> findByRole(Role role) {
        return jpa.findByRolesContaining(role.name()).stream()
                .map(mapper::toDomain)
                .toList();
    }

    @Override
    public void save(AuthUser user) {
        AuthUserEntity entity = mapper.toEntity(user);
        jpa.save(entity);
    }

    @Override
    public void delete(AuthUser authUser) {
        UUID id = authUser.getId().getValue();
        if (jpa.existsById(id)) {
            jpa.deleteById(id);
        }
    }
}