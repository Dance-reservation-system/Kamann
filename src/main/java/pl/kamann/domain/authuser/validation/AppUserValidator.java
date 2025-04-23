package pl.kamann.domain.authuser.validation;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.StatusCodes;
import pl.kamann.infrastructure.handler.ApiException;

@Component
public class AppUserValidator {

    public void validateAppUser(AppUser appUser) {
        if (appUser == null) {
            throw new ApiException(
                "AppUser not found",
                HttpStatus.NOT_FOUND,
                StatusCodes.NO_RESULTS.name()
            );
        }
    }
}