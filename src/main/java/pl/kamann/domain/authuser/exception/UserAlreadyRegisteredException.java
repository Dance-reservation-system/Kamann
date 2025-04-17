package pl.kamann.domain.authuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.attendance.AttendanceCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class UserAlreadyRegisteredException extends ApiException {
    public UserAlreadyRegisteredException() {
        super("User is already registered for this event.", HttpStatus.CONFLICT, AttendanceCodes.ALREADY_REGISTERED.name());
    }
}