package pl.kamann.application.auth.registration;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;

@Service
@RequiredArgsConstructor
public class UserPersister {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;

    @Transactional
    public void save(AuthUser authUser, AppUser appUser) {
        authUserRepository.save(authUser);
        appUserRepository.save(appUser);
    }
}