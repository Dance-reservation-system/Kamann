package pl.kamann.application.appuser;

import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.vo.Role;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.UUID;
import java.util.stream.Collectors;

@Component("applicationAppUserMapper")
public class AppUserMapperImpl implements AppUserMapper {

    @Override
    public AppUserDto toAppUserDto(AppUser user) {
        if (user == null) {
            return null;
        }
        return AppUserDto.builder()
                // ---- ID conversion ----
                // if your domain ID is a Long, and your DTO wants a UUID,
                // pick a strategy—e.g. namespace‐UUID from the Long:
                .id(UUID.nameUUIDFromBytes(user.getId().getValue().toString().getBytes()))
                // ---- Auth info ----
                .email(user.getAuthUser().getEmail().value())
                // ---- Profile fields ----
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .status(user.getStatus().name())
                .phone(user.getPhone())
                .build();
    }

    @Override
    public AppUserResponseDto toAppUserResponseDto(AppUser user) {
        if (user == null) {
            return null;
        }
        // Only the basic info for auth responses
        return new AppUserResponseDto(
                user.getAuthUser().getEmail().value(),
                user.getFirstName(),
                user.getLastName()
        );
    }

    @Override
    public AppUserProfileDto toProfileDto(AppUser user) {
        if (user == null) {
            return null;
        }
        // Convert the domain Instant → LocalDateTime for the DTO
        LocalDateTime registeredAt = LocalDateTime.ofInstant(
                user.getCreatedAt(),
                ZoneId.systemDefault()
        );
        // Flatten roles to a comma-separated String
        String role = user.getAuthUser().getRoles().stream()
                .map(Role::name)
                .collect(Collectors.joining(","));

        return new AppUserProfileDto(
                // same ID strategy as above
                UUID.nameUUIDFromBytes(user.getId().getValue().toString().getBytes()),
                // “username” here, mapped to the email address
                user.getAuthUser().getEmail().value(),
                user.getAuthUser().getEmail().value(),
                user.getStatus(),
                registeredAt,
                role
        );
    }
}
