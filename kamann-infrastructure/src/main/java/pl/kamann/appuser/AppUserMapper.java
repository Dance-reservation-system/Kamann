package pl.kamann.appuser;

import org.mapstruct.Mapper;
import pl.kamann.appuser.entity.AppUserEntity;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.vo.AppUserId;

@Mapper(componentModel = "spring")
public interface AppUserMapper {

    AppUser toDomain(AppUserEntity entity);

    AppUserEntity toEntity(AppUser domain);

    default AppUserId map(Long value) {
        return new AppUserId(value);
    }

    default Long map(AppUserId id) {
        return id.getValue();
    }


}