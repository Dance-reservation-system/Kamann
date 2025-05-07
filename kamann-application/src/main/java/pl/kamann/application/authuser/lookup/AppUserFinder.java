package pl.kamann.application.authuser.lookup;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class AppUserFinder {

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;

    public Optional<AppUser> findByAuthUser(AuthUser authUser) {
        return appUserRepository.findByAuthUser(authUser);
    }

    public Optional<AppUser> findByEmail(String email) {
        return appUserRepository.findByAuthUser_Email_Value(email);
    }

    public Optional<AuthUser> findUserByEmail(Email email) {
        return authUserRepository.findByEmail(email);
    }
}