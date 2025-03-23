package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.dmfs.rfc5545.DateTime;
import org.dmfs.rfc5545.recur.RecurrenceRule;
import org.dmfs.rfc5545.recur.RecurrenceRuleIterator;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.recurrence.RecurrenceStrategy;
import pl.kamann.config.recurrence.RecurrenceStrategyFactory;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.OccurrenceEventRepository;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OccurrenceEventGeneratorService {

    private final OccurrenceEventRepository occurrenceEventRepository;

    @Transactional
    public void createOccurrencesForEvent(Event event, LocalDateTime until) {
        RecurrenceStrategy strategy = RecurrenceStrategyFactory.getStrategy(event);
        if (strategy == null) return;

        List<LocalDateTime> dates = strategy.generateOccurrences(event, until);

        Set<LocalDateTime> existingOccurrences = new HashSet<>(
                occurrenceEventRepository.findStartDatesByEventId(event.getId())
        );

        dates.stream()
                .filter(date -> !existingOccurrences.contains(date))
                .map(date -> createSingleOccurrence(event, date))
                .forEach(occurrenceEventRepository::save);
    }

    public List<OccurrenceEvent> generateOccurrences(Event event) {
        List<OccurrenceEvent> occurrences = new ArrayList<>();

        // If no RRULE is provided, create a single occurrence (one-time event)
        if (event.getRrule() == null || event.getRrule().isEmpty()) {
            occurrences.add(createOccurrenceSeries(event, event.getStart(), 0));
            return occurrences;
        }

        try {
            RecurrenceRule rule = new RecurrenceRule(event.getRrule());
            DateTime dtStart = new DateTime(
                    event.getStart().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
            );
            RecurrenceRuleIterator iterator = rule.iterator(dtStart);

            // todo: At the moment we are using a limit to avoid infinite loops if the RRULE lacks an UNTIL or COUNT
            //  system variable might be used
            int maxInstances = 25;
            int seriesIndex = 1;
            while (iterator.hasNext() && maxInstances-- > 0) {
                DateTime nextDateTime = iterator.nextDateTime();
                LocalDateTime occurrenceStart = LocalDateTime.ofInstant(
                        Instant.ofEpochMilli(nextDateTime.getTimestamp()),
                        ZoneId.systemDefault()
                );
                occurrences.add(createOccurrenceSeries(event, occurrenceStart, seriesIndex++));
            }
        } catch (Exception e) {
            throw new ApiException(
                    "Failed to generate occurrences: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    EventCodes.OCCURRENCE_GENERATION_FAILED.name());
        }

        return occurrences;
    }

    private OccurrenceEvent createSingleOccurrence(Event event, LocalDateTime start) {
        return OccurrenceEvent.builder()
                .event(event)
                .start(start)
                .durationMinutes(event.getDurationMinutes())
                .maxParticipants(event.getMaxParticipants())
                .instructor(event.getInstructor())
                .seriesIndex(0)
                .build();
    }

    private OccurrenceEvent createOccurrenceSeries(Event event, LocalDateTime start, int seriesIndex) {
        return OccurrenceEvent.builder()
                .event(event)
                .start(start)
                .createdBy(event.getCreatedBy())
                .durationMinutes(event.getDurationMinutes())
                .maxParticipants(event.getMaxParticipants())
                .instructor(event.getInstructor())
                .seriesIndex(seriesIndex)
                .build();
    }
}