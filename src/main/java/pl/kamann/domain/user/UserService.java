package pl.kamann.domain.user;

import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.AppUserRepository;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.dto.RegisterRequest;

public interface UserService {
    AppUser createAppUserFromRegistration(RegisterRequest request);
    AuthUser createAndLinkAuthUserWithApp(RegisterRequest request, Role role, AppUser appUser);
    void saveNewUser(AuthUser authUser, AppUser appUser);
}