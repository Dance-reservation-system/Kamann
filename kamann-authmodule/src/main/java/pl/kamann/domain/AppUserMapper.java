package pl.kamann.domain;

import org.springframework.stereotype.Component;
import pl.kamann.application.AppUserId;
import pl.kamann.infrastructure.AppUserEntity;

@Component
public class AppUserMapper {

    public AppUserEntity toEntity(AppUser domain) {
        AppUserEntity entity = new AppUserEntity();
        entity.setFirstName(domain.getFirstName());
        entity.setLastName(domain.getLastName());
        entity.setPhone(domain.getPhone());
        entity.setCreatedAt(domain.getCreatedAt());
        entity.setUpdatedAt(domain.getUpdatedAt());

        return entity;
    }

    public AppUser toDomain(AppUserEntity entity, AuthUser authUser) {
        return new AppUser(
                new AppUserId(entity.getId()),
                authUser,
                entity.getFirstName(),
                entity.getLastName(),
                entity.getPhone(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }
}