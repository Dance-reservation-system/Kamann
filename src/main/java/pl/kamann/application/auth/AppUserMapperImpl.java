package pl.kamann.application.auth;

import org.springframework.stereotype.Component;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;

import java.util.Optional;
import java.util.UUID;

@Component
class AppUserMapperImpl implements AppUserMapper {

    @Override
    public AppUserDto toAppUserDto(AppUser user) {
        if (user == null) {
            return null;
        }

        UUID id = Optional.ofNullable(user.getId())
                .map(idVal -> UUID.fromString(idVal.getValue().toString()))
                .orElse(null);

        AuthUser authUser = user.getAuthUser();

        String email = Optional.ofNullable(authUser)
                .map(a -> a.getEmail().value())
                .orElse(null);

        String firstName = user.getFirstName();
        String lastName = user.getLastName();

        String status = Optional.ofNullable(authUser)
                .map(AuthUser::getStatus)
                .map(Enum::name)
                .orElse(null);

        String phone = user.getPhone();

        return new AppUserDto(id, email, firstName, lastName, status, phone);
    }

    @Override
    public AppUserResponseDto toAppUserResponseDto(AppUser user) {
        if (user == null) {
            return null;
        }

        AuthUser authUser = user.getAuthUser();

        String email = Optional.ofNullable(authUser)
                .map(a -> a.getEmail().value())
                .orElse(null);

        return new AppUserResponseDto(email, user.getFirstName(), user.getLastName());
    }
}
