package pl.kamann.application.appuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.lookup.AppUserFinder;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.vo.AuthUserStatus;

@Service
@RequiredArgsConstructor
public class AppUserCommandService {

    private final AppUserFinder appUserFinder;
    private final AppUserMapper appUserMapper;

    @Transactional
    public AppUserDto changeUserStatus(Long userId, AuthUserStatus status) {
        AppUser user = appUserFinder.findUserByIdWithAuth(userId);
        user.changeStatus(status);
        return appUserMapper.toAppUserDto(user);
    }

    @Transactional
    public void activateUser(Long userId) {
        AppUser user = appUserFinder.findUserByIdWithAuth(userId);
        user.activate();
    }

    @Transactional
    public void deactivateUser(Long userId) {
        AppUser user = appUserFinder.findUserByIdWithAuth(userId);
        user.deactivate();
    }
}
