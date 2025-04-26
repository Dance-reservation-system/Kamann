package pl.kamann.domain.appuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class UserNotFoundException extends ApiException {
    public UserNotFoundException() {
        super("User not found.", HttpStatus.NOT_FOUND, AuthCodes.USER_NOT_FOUND.name());
    }
}