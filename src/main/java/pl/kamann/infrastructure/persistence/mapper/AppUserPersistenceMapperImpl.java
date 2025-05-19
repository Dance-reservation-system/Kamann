package pl.kamann.infrastructure.persistence.mapper;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.vo.AppUserId;
import pl.kamann.infrastructure.persistence.jpa.AppUserEntity;
import pl.kamann.infrastructure.persistence.jpa.AuthUserEntity;
import pl.kamann.infrastructure.persistence.jpa.JpaAuthUserRepository;

@Component
@RequiredArgsConstructor
public class AppUserPersistenceMapperImpl implements AppUserPersistenceMapper {

    private final AuthUserPersistenceMapper authUserMapper;
    private final JpaAuthUserRepository jpaAuthUserRepository;

    @Override
    public AppUser toDomain(AppUserEntity entity) {
        return new AppUser(
                new AppUserId(entity.getId()),
                authUserMapper.toDomain(entity.getAuthUser()),
                entity.getFirstName(),
                entity.getLastName(),
                entity.getPhone(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    @Override
    public AppUserEntity toEntity(AppUser domain) {
        AppUserEntity entity = new AppUserEntity();
        entity.setId(domain.getId().getValue());

        AuthUser authUser = domain.getAuthUser();
        AuthUserEntity authUserEntity = authUserMapper.toEntity(authUser);

        // Prevent invalid merge: nullify ID if record not in DB
        if (authUser.getId() != null && !jpaAuthUserRepository.existsById(authUser.getId().getValue())) {
            authUserEntity.setId(null);
        }

        entity.setAuthUser(authUserEntity);
        entity.setFirstName(domain.getFirstName());
        entity.setLastName(domain.getLastName());
        entity.setPhone(domain.getPhone());
        entity.setCreatedAt(domain.getCreatedAt());
        entity.setUpdatedAt(domain.getUpdatedAt());
        return entity;
    }
}
