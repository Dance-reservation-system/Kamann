package pl.kamann.domain.appuser;

import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.AuthUser;

@Component
public class AppUserFactory {

    public AppUser create(AppUserProfile profile, AuthUser authUser) {
        return AppUser.create(profile, authUser);
    }
}