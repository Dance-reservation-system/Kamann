/**
 * Ubiquitous Language Summary:
 * Domain coordination factory that builds the full user aggregate structure,
 * linking AppUser and AuthUser based on raw input.
 */
package pl.kamann.domain.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.application.auth.PasswordHasher;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.AppUserFactory;
import pl.kamann.domain.appuser.AppUserProfile;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.authuser.Password;
import pl.kamann.infrastructure.security.RawAuthUserInput;

@Component
@RequiredArgsConstructor
public class UserFactory {

    private final AppUserFactory appUserFactory;
    private final PasswordHasher passwordHasher;

    public UserAggregate createFullUser(String firstName, String lastName, String phone, RawAuthUserInput rawUser) {
        AppUserProfile profile = AppUserProfile.create(firstName, lastName, phone);
        AppUser appUser = appUserFactory.create(profile, null);

        Email email = new Email(rawUser.email());
        Password password = new Password(rawUser.password(), passwordHasher);

        AuthUser authUser = AuthUser.create(
                email,
                password,
                rawUser.roles(),
                AuthUserStatus.PENDING_CONFIRMATION,
                appUser
        );

        return new UserAggregate(authUser, appUser);
    }

    public record UserAggregate(AuthUser authUser, AppUser appUser) {}
}
