package pl.kamann.domain.user.implementation;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.user.UserAccountService;

@Service
@RequiredArgsConstructor
public class UserAccountServiceImpl implements UserAccountService {

    private final AuthUserRepository authUserRepository;

    @Override
    public void changeStatus(AuthUser authUser, AuthUserStatus status) {
        authUser.setStatus(status);
        if (status == AuthUserStatus.ACTIVE) {
            authUser.setEnabled(true);
        } else if (status == AuthUserStatus.INACTIVE) {
            authUser.setEnabled(false);
        }
        authUserRepository.save(authUser);
        // Opublikuj zdarzenie domenowe UserStatusChanged
    }

    @Override
    public void activate(AuthUser authUser) {
        changeStatus(authUser, AuthUserStatus.ACTIVE);
    }

    @Override
    public void deactivate(AuthUser authUser) {
        changeStatus(authUser, AuthUserStatus.INACTIVE);
    }
}