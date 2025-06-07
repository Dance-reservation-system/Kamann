package pl.kamann.infrastructure.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;
import pl.kamann.domain.repository.AppUserRepository;
import pl.kamann.domain.vo.AppUserId;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.infrastructure.persistence.jpa.AppUserEntity;
import pl.kamann.infrastructure.persistence.jpa.AuthUserEntity;
import pl.kamann.infrastructure.persistence.jpa.JpaAppUserRepository;
import pl.kamann.infrastructure.persistence.mapper.AppUserPersistenceMapper;
import pl.kamann.infrastructure.persistence.mapper.AuthUserPersistenceMapper;

import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class JpaAppUserRepositoryAdapter implements AppUserRepository {

    private final JpaAppUserRepository jpa;
    private final AppUserPersistenceMapper mapper;
    private final AuthUserPersistenceMapper authMapper;

    @Override
    public Optional<AppUser> findByAuthUser(AuthUser authUser) {
        AuthUserEntity authEntity = authMapper.toEntity(authUser);
        return jpa.findByAuthUser(authEntity)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findById(AppUserId id) {
        return jpa.findById(id.getValue())
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findByAuthUser_Email_Value(String email) {
        return jpa.findByAuthUser_Email(email)
                .map(mapper::toDomain);
    }

    @Override
    public Optional<AppUser> findByIdWithAuth(UUID id) {
        return jpa.findByIdWithAuth(id)
                .map(mapper::toDomain);
    }

    @Override
    public void save(AppUser user) {
        AppUserEntity entity = mapper.toEntity(user);
        jpa.save(entity);
    }
}