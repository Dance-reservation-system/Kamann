package pl.kamann.domain.event.exceptions;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class EventTypeNotFoundException extends ApiException {
    public EventTypeNotFoundException() {
        super("Event type not found.", HttpStatus.NOT_FOUND, EventCodes.EVENT_TYPE_NOT_FOUND.name());
    }
}