package pl.kamann.domain.event;

import pl.kamann.domain.event.model.Event;

import java.time.LocalDateTime;
import java.util.List;

public interface RecurrenceStrategy {
    List<LocalDateTime> generateOccurrences(Event event, LocalDateTime until);
}