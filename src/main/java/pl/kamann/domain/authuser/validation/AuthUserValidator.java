package pl.kamann.domain.authuser.validation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.Email;
import pl.kamann.infrastructure.handler.ApiException;

@Component
@RequiredArgsConstructor
public class AuthUserValidator {

    private final AuthUserRepository authUserRepository;

    public void validateEmailNotTaken(Email email) {
        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new ApiException(
                "Email is already registered: " + email,
                HttpStatus.CONFLICT,
                "EMAIL_ALREADY_EXISTS"
            );
        }
    }

    public void validateStatusNotNull(AuthUserStatus status) {
        if (status == null) {
            throw new ApiException("Status cannot be null", HttpStatus.BAD_REQUEST, "INVALID_INPUT");
        }
    }

    public void validateExists(AuthUser authUser) {
        if (authUser == null) {
            throw new ApiException("AuthUser not found", HttpStatus.NOT_FOUND, "NO_RESULTS");
        }
    }
}