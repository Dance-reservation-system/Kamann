package pl.kamann.domain.event;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class WeeklyRecurrenceStrategy implements RecurrenceStrategy {
    @Override
    public List<LocalDateTime> generateOccurrences(Event event, LocalDateTime until) {
        List<LocalDateTime> occurrences = new ArrayList<>();
        LocalDateTime current = event.getStart();
        while (!current.isAfter(until)) {
            occurrences.add(current);
            current = current.plusWeeks(1);
        }
        return occurrences;
    }
}