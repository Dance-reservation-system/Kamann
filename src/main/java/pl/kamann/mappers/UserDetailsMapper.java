package pl.kamann.mappers;

import org.mapstruct.BeanMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;

@Mapper(componentModel = "spring")
public interface UserDetailsMapper {
    @BeanMapping(nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
    @Mapping(target = "email", source = "appUser.authUser.email")
    @Mapping(target = "phone", source = "appUser.phone")
    @Mapping(target = "firstName", source = "appUser.firstName")
    @Mapping(target = "lastName", source = "appUser.lastName")
    UserDetailsDto toUserDetailsDto(AppUser appUser);
}