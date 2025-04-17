package pl.kamann.domain.user.implementation;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.AppUserRepository;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.domain.user.UserFactory;
import pl.kamann.domain.user.UserService;
import org.springframework.security.crypto.password.PasswordEncoder; // Dodajemy PasswordEncoder

@Service
@RequiredArgsConstructor
class UserServiceImpl implements UserService {

    private final UserFactory userFactory;
    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder; // Wstrzykujemy PasswordEncoder

    @Override
    public AppUser createAppUserFromRegistration(RegisterRequest request) {
        return userFactory.createAppUser(request);
    }

    @Override
    public AuthUser createAndLinkAuthUserWithApp(RegisterRequest request, Role role, AppUser appUser) {
        return AuthUser.create(request.email(), passwordEncoder.encode(request.password()), java.util.Set.of(role), AuthUserStatus.PENDING_CONFIRMATION);
    }

    @Override
    public void saveNewUser(AuthUser authUser, AppUser appUser) {
        authUserRepository.save(authUser);
        appUserRepository.save(appUser);
    }
}