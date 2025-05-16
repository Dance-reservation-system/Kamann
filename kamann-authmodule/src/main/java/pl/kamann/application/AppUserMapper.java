package pl.kamann.application;


import pl.kamann.domain.AppUser;

public interface AppUserMapper {

    AppUserDto toAppUserDto(AppUser user);

    AppUserResponseDto toAppUserResponseDto(AppUser user);

    AppUserProfileDto toProfileDto(AppUser user);

}
