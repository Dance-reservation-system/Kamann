package pl.kamann.domain.event;

import java.time.LocalDateTime;
import java.util.List;

public interface RecurrenceStrategy {
    List<LocalDateTime> generateOccurrences(Event event, LocalDateTime until);
}