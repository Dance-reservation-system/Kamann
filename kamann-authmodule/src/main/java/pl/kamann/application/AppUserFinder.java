package pl.kamann.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.AppUser;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.Email;
import pl.kamann.infrastructure.AppUserRepository;
import pl.kamann.infrastructure.AuthUserRepository;


import java.util.Optional;
import java.util.UUID;

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

    public AppUser findUserByIdWithAuth(UUID userId) {
        return appUserRepository.findByIdWithAuth(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
    }

    public AppUser findAppUserByAuthUser(AuthUser authUser) {
        return appUserRepository.findByAuthUser(authUser)
                .orElseThrow(() -> new RuntimeException("AppUser not found for AuthUser: " + authUser.getId()));
    }
}