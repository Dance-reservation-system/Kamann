package pl.kamann.appuser.repository;

import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

import pl.kamann.appuser.AppUserMapper;
import pl.kamann.appuser.entity.AppUserEntity;
import pl.kamann.authuser.AuthUserPersistenceMapper;
import pl.kamann.authuser.entity.AuthUserEntity;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.vo.AppUserId;

@Component("persistenceAppUserMapper")
@RequiredArgsConstructor
public class AppUserMapperImpl implements AppUserMapper {

    private final AuthUserPersistenceMapper authUserMapper;

    @Override
    public AppUser toDomain(AppUserEntity entity) {
        if (entity == null) return null;

        // map the nested AuthUserEntity → domain AuthUser
        var authUser = authUserMapper.toDomain(entity.getAuthUser());

        // wrap the Long → AppUserId
        var appUserId = new AppUserId(entity.getId());

        // if your entity has more fields (phone, timestamps, etc.) map them too
        return new AppUser(
            appUserId,
            authUser,
            entity.getFirstName(),
            entity.getLastName(),
            /* phone: */ null,             // or entity.getPhone() if you add it
            /* createdAt: */ null,         // or entity.getCreatedAt()
            /* updatedAt: */ null          // or entity.getUpdatedAt()
        );
    }

    @Override
    public AppUserEntity toEntity(AppUser domain) {
        if (domain == null) return null;

        var e = new AppUserEntity();
        e.setId(domain.getId().getValue());
        e.setFirstName(domain.getFirstName());
        e.setLastName(domain.getLastName());
        // cascade the email into your AppUserEntity.email column
        e.setEmail(domain.getAuthUser().getEmail().value());

        // only set the FK association; JPA will handle the rest
        AuthUserEntity au = new AuthUserEntity();
        au.setId(domain.getAuthUser().getId().getValue());
        e.setAuthUser(au);

        // if you add phone/createdAt/updatedAt to the entity, set them here too

        return e;
    }
}
