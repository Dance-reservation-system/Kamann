package pl.kamann.infrastructure;

import pl.kamann.application.AppUserId;
import pl.kamann.domain.AppUser;

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
