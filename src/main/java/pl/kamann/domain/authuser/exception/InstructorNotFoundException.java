package pl.kamann.domain.authuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.InstructorCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class InstructorNotFoundException extends ApiException {
    public InstructorNotFoundException() {
        super("Instructor not found.", HttpStatus.NOT_FOUND, InstructorCodes.INSTRUCTOR_NOT_FOUND.name());
    }
}