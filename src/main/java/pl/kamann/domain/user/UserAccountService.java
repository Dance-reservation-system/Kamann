package pl.kamann.domain.user;

import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;

public interface UserAccountService {
    void changeStatus(AuthUser authUser, AuthUserStatus status);
    void activate(AuthUser authUser);
    void deactivate(AuthUser authUser);
}