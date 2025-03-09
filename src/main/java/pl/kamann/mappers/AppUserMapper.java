package pl.kamann.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.config.pagination.PaginatedResponseDto;
import pl.kamann.dtos.AppUserDto;
import pl.kamann.dtos.AppUserResponseDto;
import pl.kamann.entities.appuser.AppUser;

@Mapper(componentModel = "spring")
public interface AppUserMapper {

    @Mapping(source = "authUser.email", target = "email")
    @Mapping(source = "authUser.status", target = "status")
    AppUserDto toAppUserDto(AppUser user);

    PaginatedResponseDto<AppUserDto> toPaginatedResponseDto(PaginatedResponseDto<AppUser> users);

    AppUserResponseDto toAppUserResponseDto(AppUser loggedInUser);
}