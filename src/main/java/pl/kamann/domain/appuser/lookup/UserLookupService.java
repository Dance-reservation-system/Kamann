package pl.kamann.domain.appuser.lookup;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.infrastructure.handler.ApiException;

import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserLookupService {

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;

    public AppUser findUserByIdWithAuth(Long userId) {
        return findUserById(userId);
    }

    public AppUser findUserById(Long userId) {
        return appUserRepository.findById(userId)
                .orElseThrow(() -> new ApiException(
                        "User not found with ID: " + userId,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()
                ));
    }

    public AppUser findAppUserByAuthUser(AuthUser authUser) {
        return appUserRepository.findByAuthUser(authUser)
                .orElseThrow(() -> new ApiException(
                        "AppUser not found for the given AuthUser",
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));
    }

    public Optional<AppUser> findUserByEmail(String email) {
        return appUserRepository.findByAuthUser_Email_Value(email);
    }
}
