package pl.kamann.application.appuser;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.vo.AppUserId;
import pl.kamann.domain.authuser.vo.Email;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Mapper(componentModel = "spring")
public interface AppUserMapper {

    @Mapping(source = "authUser.email",  target = "email")
    @Mapping(source = "authUser.status", target = "status")
    @Mapping(source = "id",              target = "id")
    @Mapping(source = "firstName",       target = "firstName")
    @Mapping(source = "lastName",        target = "lastName")
    @Mapping(source = "phone",           target = "phone")
    AppUserDto toAppUserDto(AppUser user);

    @Mapping(source = "authUser.email",  target = "email")
    @Mapping(source = "firstName",       target = "firstName")
    @Mapping(source = "lastName",        target = "lastName")
    AppUserResponseDto toAppUserResponseDto(AppUser user);

    @Mapping(source = "createdAt",       target = "registeredAt")
    AppUserProfileDto toProfileDto(AppUser user);

    // Manual mapping methods
    default String map(Email email) {
        return email != null ? email.value() : null;
    }

    default UUID map(AppUserId id) {
        return id != null ? id.getValue() : null;
    }

    default LocalDateTime map(Instant instant) {
        return instant != null ? LocalDateTime.ofInstant(instant, ZoneOffset.UTC) : null;
    }
}
