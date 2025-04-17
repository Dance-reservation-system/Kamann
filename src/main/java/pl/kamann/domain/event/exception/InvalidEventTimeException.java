package pl.kamann.domain.event.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class InvalidEventTimeException extends ApiException {
    public InvalidEventTimeException() {
        super("Invalid time specified for the event.", HttpStatus.BAD_REQUEST, EventCodes.INVALID_EVENT_TIME.name());
    }
}