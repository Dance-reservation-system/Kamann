package pl.kamann.domain.factory;

import org.springframework.stereotype.Component;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.service.AppUserPolicy;
import pl.kamann.domain.service.AuthUserPolicy;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.Password;
import pl.kamann.domain.vo.Role;

import java.util.Set;

@Component
public class UserAccountFactory {

    private final AuthUserPolicy authUserPolicy;
    private final AppUserPolicy appUserPolicy;

    public UserAccountFactory(AuthUserPolicy authUserPolicy, AppUserPolicy appUserPolicy) {
        this.authUserPolicy = authUserPolicy;
        this.appUserPolicy = appUserPolicy;
    }

    public AuthUser createCustomerAuthUser(Email email, String password) {
        Password passwordVO = new Password(password);
        Set<Role> roles = Set.of(Role.CUSTOMER);
        return AuthUser.register(email, passwordVO, roles, authUserPolicy);
    }

    public AuthUser createInstructorAuthUser(Email email, String password) {
        Password passwordVO = new Password(password);
        Set<Role> roles = Set.of(Role.INSTRUCTOR);
        return AuthUser.register(email, passwordVO, roles, authUserPolicy);
    }

    public AppUser createAppUser(AuthUser authUser, String firstName, String lastName, String phone) {
        return AppUser.create(authUser, firstName, lastName, phone, appUserPolicy);
    }
}