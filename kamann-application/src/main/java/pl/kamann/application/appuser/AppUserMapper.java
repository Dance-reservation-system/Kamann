package pl.kamann.application.appuser;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.vo.Email;

@Mapper(componentModel = "spring")
public interface AppUserMapper {

    // Map full user view
    @Mapping(source = "authUser.email",       target = "email")
    @Mapping(source = "authUser.status",      target = "status")
    @Mapping(source = "id",                   target = "id")
    @Mapping(source = "firstName",            target = "firstName")
    @Mapping(source = "lastName",             target = "lastName")
    @Mapping(source = "phone",                target = "phone")
    @Mapping(source = "createdAt",            target = "createdAt")
    @Mapping(source = "updatedAt",            target = "updatedAt")
    AppUserDto toAppUserDto(AppUser user);

    // Map response DTO (e.g. after login)
    @Mapping(source = "authUser.email",       target = "email")
    @Mapping(source = "firstName",            target = "firstName")
    @Mapping(source = "lastName",             target = "lastName")
    AppUserResponseDto toAppUserResponseDto(AppUser user);

    default String map(Email email) {
        return email != null ? email.getValue() : null;
    }

    // Map profile view, renaming createdAt → registeredAt
    @Mapping(source = "firstName",            target = "firstName")
    @Mapping(source = "lastName",             target = "lastName")
    @Mapping(source = "phone",                target = "phone")
    @Mapping(source = "createdAt",            target = "registeredAt")
    @Mapping(source = "updatedAt",            target = "lastUpdatedAt")
    AppUserProfileDto toProfileDto(AppUser user);
}
