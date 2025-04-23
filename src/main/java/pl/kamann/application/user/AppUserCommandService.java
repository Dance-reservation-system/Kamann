package pl.kamann.application.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.AuthUserStatus;

@Service
@RequiredArgsConstructor
public class AppUserCommandService {

    private final UserLookupService userLookupService;
    private final AppUserMapper appUserMapper;

    @Transactional
    public AppUserDto changeUserStatus(Long userId, AuthUserStatus status) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        user.getAuthUser().changeStatus(status);
        return appUserMapper.toAppUserDto(user);
    }

    @Transactional
    public void activateUser(Long userId) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        user.activate();
    }

    @Transactional
    public void deactivateUser(Long userId) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        user.deactivate();
    }
}
