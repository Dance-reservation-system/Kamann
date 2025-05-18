package pl.kamann.application.auth;


import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.domain.entity.AppUser;

interface AppUserMapper {

    AppUserDto toAppUserDto(AppUser user);

    AppUserResponseDto toAppUserResponseDto(AppUser user);

}
