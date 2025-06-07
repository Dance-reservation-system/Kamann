package pl.kamann.domain.authuser.factory;

import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.service.AppUserPolicy;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.service.AuthUserPolicy;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Password;
import pl.kamann.domain.authuser.vo.Role;

import java.util.Set;

@Component
public class UserAccountFactory {

    private final AuthUserPolicy authUserPolicy;
    private final AppUserPolicy appUserPolicy;

    public UserAccountFactory(AuthUserPolicy authUserPolicy, AppUserPolicy appUserPolicy) {
        this.authUserPolicy = authUserPolicy;
        this.appUserPolicy = appUserPolicy;
    }

    public UserAccount createClient(String email, String password, String firstName, String lastName, String phone) {
        Email emailVO = new Email(email);
        Password passwordVO = new Password(password);
        Set<Role> roles = Set.of(Role.CUSTOMER);

        AuthUser authUser = AuthUser.register(emailVO, passwordVO, roles, authUserPolicy);
        AppUser appUser = AppUser.create(authUser, firstName, lastName, phone, appUserPolicy);

        return new UserAccount(authUser, appUser);
    }

    public UserAccount createInstructor(String email, String password, String firstName, String lastName, String phone) {
        Email emailVO = new Email(email);
        Password passwordVO = new Password(password);
        Set<Role> roles = Set.of(Role.INSTRUCTOR);

        AuthUser authUser = AuthUser.register(emailVO, passwordVO, roles, authUserPolicy);
        AppUser appUser = AppUser.create(authUser, firstName, lastName, phone, appUserPolicy);

        return new UserAccount(authUser, appUser);
    }
    public record UserAccount(AuthUser authUser, AppUser appUser) {}
}