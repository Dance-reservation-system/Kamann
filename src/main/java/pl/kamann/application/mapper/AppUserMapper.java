package pl.kamann.application.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.dto.AppUserResponseDto;
import pl.kamann.domain.authuser.Email;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;

@Mapper(componentModel = "spring")
public interface AppUserMapper {

    @Mapping(source = "authUser.email", target = "email")
    @Mapping(source = "authUser.status", target = "status")
    AppUserDto toAppUserDto(AppUser user);

    PaginatedResponseDto<AppUserDto> toPaginatedResponseDto(PaginatedResponseDto<AppUser> users);

    AppUserResponseDto toAppUserResponseDto(AppUser loggedInUser);

    default String map(Email email) {
        return email != null ? email.getValue() : null;
    }
}