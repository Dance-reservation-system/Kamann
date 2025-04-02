package pl.kamann.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;

@Mapper(componentModel = "spring")
public interface UserDetailsMapper {
    @Mapping(target = "email", source = "authUser.email")
    @Mapping(target = "phone", source = "appUser.phone")
    @Mapping(target = "firstName", source = "appUser.firstName")
    @Mapping(target = "lastName", source = "appUser.lastName")
    @Mapping(target = "roles", source = "appUser.authUser.roles", qualifiedByName = "mapRolesToStrings")
    UserDetailsDto toUserDetailsDto(AppUser appUser);

    @Named("mapRolesToStrings")
    default Set<String> mapRolesToStrings(Set<Role> roles) {
        return roles != null ? roles.stream()
                .map(Role::getName)
                .collect(Collectors.toSet()) : new HashSet<>();
    }
}