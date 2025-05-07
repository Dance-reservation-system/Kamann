package pl.kamann.domain.event.exceptions;


import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class EventNotFoundException extends ApiException {
    public EventNotFoundException() {
        super("Event not found.", HttpStatus.NOT_FOUND, EventCodes.EVENT_NOT_FOUND.name());
    }
}