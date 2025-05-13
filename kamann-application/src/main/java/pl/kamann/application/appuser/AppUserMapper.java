package pl.kamann.application.appuser;

import pl.kamann.domain.appuser.aggregate.AppUser;

public interface AppUserMapper {

    AppUserDto toAppUserDto(AppUser user);

    AppUserResponseDto toAppUserResponseDto(AppUser user);

    AppUserProfileDto toProfileDto(AppUser user);

}
