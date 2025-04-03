package pl.kamann.config.exception.specific;

import org.springframework.http.HttpStatus;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;

public class OccurrenceEventNotFoundException extends ApiException {
    public OccurrenceEventNotFoundException() {
        super("Occurrence event not found.", HttpStatus.NOT_FOUND, EventCodes.OCCURRENCE_NOT_FOUND.name());
    }
}
