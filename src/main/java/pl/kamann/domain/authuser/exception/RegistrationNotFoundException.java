package pl.kamann.domain.authuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.InstructorCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class RegistrationNotFoundException extends ApiException {
    public RegistrationNotFoundException() {
        super("Registration not found.", HttpStatus.NOT_FOUND, InstructorCodes.REGISTRATION_NOT_FOUND.name());
    }
}