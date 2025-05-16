package pl.kamann.infrastructure;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.AuthUserEntity;
import pl.kamann.domain.Email;
import pl.kamann.domain.Role;

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