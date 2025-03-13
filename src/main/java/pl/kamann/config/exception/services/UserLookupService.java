package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;

@RequiredArgsConstructor
@Service
public class UserLookupService {

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;
    private final ValidationService validationService;

    public AppUser findUserByIdWithAuth(Long userId) {
        AppUser user = findUserById(userId);

        validationService.validateAppUser(user);
        validationService.validateAuthUser(user.getAuthUser());

        return user;
    }

    public AppUser findUserById(Long userId) {
        validationService.validateUserId(userId);

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


    public AppUser findUserByEmail(String email) {
        return authUserRepository.findByEmail(email)
                .map(authUser -> {
                    validationService.validateAuthUser(authUser);

                    AppUser appUser = authUser.getAppUser();
                    validationService.validateAppUser(appUser);

                    return appUser;
                })
                .orElseThrow(() -> new ApiException(
                        "User not found with email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));
    }

    public AppUser getLoggedInUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return findUserByEmail(email);
    }
}
