package pl.kamann.domain.authuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.InstructorCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class InstructorBusyException extends ApiException {
    public InstructorBusyException() {
        super("Instructor is busy during the requested time slot.", HttpStatus.CONFLICT, InstructorCodes.INSTRUCTOR_BUSY.name());
    }
}