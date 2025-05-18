package pl.kamann.infrastructure.persistence.mapper;

import pl.kamann.domain.vo.AppUserId;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.infrastructure.persistence.jpa.AppUserEntity;

import java.util.UUID;

public interface AppUserPersistenceMapper {

    AppUser toDomain(AppUserEntity entity);

    AppUserEntity toEntity(AppUser domain);

    default AppUserId map(UUID id) {
        return new AppUserId(id);
    }

    default UUID map(AppUserId id) {
        return id.getValue();
    }
}
