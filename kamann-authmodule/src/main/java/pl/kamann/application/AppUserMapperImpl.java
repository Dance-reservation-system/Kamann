package pl.kamann.application;

import org.springframework.stereotype.Component;
import pl.kamann.domain.AppUser;
import pl.kamann.domain.AuthUser;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;

@Component
public class AppUserMapperImpl implements AppUserMapper {

    @Override
    public AppUserDto toAppUserDto(AppUser user) {
        if (user == null) return null;
        AuthUser authUser = user.getAuthUser();

        return AppUserDto.builder()
                .id(user.getId() != null ? UUID.fromString(user.getId().getValue().toString()) : null)
                .email(authUser != null ? authUser.getEmail().value() : null)
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .status(authUser != null && authUser.getStatus() != null ? authUser.getStatus().name() : null)
                .phone(user.getPhone())
                .build();
    }

    @Override
    public AppUserResponseDto toAppUserResponseDto(AppUser user) {
        if (user == null) {
            return null;
        }
        AuthUser authUser = user.getAuthUser();

        return new AppUserResponseDto(
                authUser != null ? authUser.getEmail().value() : null,
                user.getFirstName(),
                user.getLastName()
        );
    }

    @Override
    public AppUserProfileDto toProfileDto(AppUser user) {
        if (user == null) {
            return null;
        }
        AuthUser authUser = user.getAuthUser();

        return new AppUserProfileDto(
                user.getId() != null ? UUID.fromString(user.getId().getValue().toString()) : null,
                user.getFirstName() + " " + user.getLastName(),
                authUser != null ? authUser.getEmail().value() : null,
                authUser != null ? authUser.getStatus() : null,
                user.getCreatedAt() != null
                        ? LocalDateTime.ofInstant(user.getCreatedAt(), ZoneId.systemDefault())
                        : null,
                authUser != null && !authUser.getRoles().isEmpty()
                        ? authUser.getRoles().iterator().next().name()
                        : null
        );
    }
}
