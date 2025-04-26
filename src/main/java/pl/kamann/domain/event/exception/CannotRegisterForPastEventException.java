package pl.kamann.domain.event.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class CannotRegisterForPastEventException extends ApiException {
    public CannotRegisterForPastEventException() {
        super("Cannot register for past events.", HttpStatus.BAD_REQUEST, EventCodes.PAST_EVENT_ERROR.name());
    }
}