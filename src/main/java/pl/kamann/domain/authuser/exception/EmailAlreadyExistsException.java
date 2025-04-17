package pl.kamann.domain.authuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class EmailAlreadyExistsException extends ApiException {
    public EmailAlreadyExistsException(String email) {
        super(String.format("Email '%s' is already registered.", email), HttpStatus.CONFLICT, AuthCodes.EMAIL_ALREADY_EXISTS.name());
    }
}