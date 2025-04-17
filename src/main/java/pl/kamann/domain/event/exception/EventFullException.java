package pl.kamann.domain.event.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class EventFullException extends ApiException {
    public EventFullException() {
        super("Event is fully booked", HttpStatus.BAD_REQUEST, "EVENT_FULL");
    }
}