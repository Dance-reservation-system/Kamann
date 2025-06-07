package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.repository.AppUserRepository;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.Email;

import java.util.Optional;
import java.util.UUID;

@Component
@RequiredArgsConstructor
class AppUserFinder {

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

    public AppUser findUserByIdWithAuth(UUID userId) {
        return appUserRepository.findByIdWithAuth(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
    }

    public AppUser findAppUserByAuthUser(AuthUser authUser) {
        return appUserRepository.findByAuthUser(authUser)
                .orElseThrow(() -> new RuntimeException("AppUser not found for AuthUser: " + authUser.getId()));
    }
}