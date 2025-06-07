package pl.kamann.appuser;

import pl.kamann.appuser.entity.AppUserEntity;
import pl.kamann.domain.appuser.aggregate.AppUser;

public interface AppUserMapper {

    AppUser toDomain(AppUserEntity entity);

    AppUserEntity toEntity(AppUser domain);

}