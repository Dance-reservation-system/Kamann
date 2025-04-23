package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.Email;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;

@Service
@RequiredArgsConstructor
public class ManageUserAccountService {

    private final AuthUserRepository authUserRepository;
    private final UserLookupService userLookupService;
    private final ScheduledTaskService scheduledTaskService;

    @Transactional
    public void requestAccountDeletion(String email) {
        AppUser appUser = userLookupService.findUserByEmail(new Email(email).getValue())
                .orElseThrow(() -> new IllegalArgumentException("User with email " + email + " not found"));

        appUser.startDeletion();
        scheduledTaskService.schedulePendingDeletionFinalization(appUser.getAuthUser());
        authUserRepository.save(appUser.getAuthUser());
    }
}