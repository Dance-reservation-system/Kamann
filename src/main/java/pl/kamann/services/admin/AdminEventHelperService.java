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
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventStatus;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.OccurrenceEventRepository;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminEventHelperService {

    private final OccurrenceEventRepository occurrenceEventRepository;
    private final UserLookupService userLookupService;

    @Transactional
    public void createOccurrenceEvents(Event event) {
        occurrenceEventRepository.saveAll(generateOccurrences(event));
    }

    @Transactional
    void cancelOccurrenceEventsAfter(Event event, LocalDateTime date) {
        List<OccurrenceEvent> futureOccurrences = occurrenceEventRepository.findByEventAndStartAfter(event, date);
        futureOccurrences.forEach(occ -> {
            occ.setCanceled(true);
            occ.setEventStatus(EventStatus.CANCELED);
        });
    }

    void deleteOccurrenceEvent(Event event) {
        occurrenceEventRepository.deleteByEvent(event);
    }

    boolean hasOccurrenceEvents(Event event) {
        return occurrenceEventRepository.existsByEvent(event);
    }

    List<OccurrenceEvent> generateOccurrences(Event event) {
        List<OccurrenceEvent> occurrences = new ArrayList<>();

        // If no RRULE is provided, create a single occurrence (one-time event)
        if (event.getRrule() == null || event.getRrule().isEmpty()) {
            occurrences.add(createOccurrence(event, event.getStart(), 0));
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
                occurrences.add(createOccurrence(event, occurrenceStart, seriesIndex++));
            }
        } catch (Exception e) {
            throw new ApiException(
                    "Failed to generate occurrences: " + e.getMessage(),
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    EventCodes.OCCURRENCE_GENERATION_FAILED.name());
        }

        return occurrences;
    }

    OccurrenceEvent createOccurrence(Event event, LocalDateTime start, int seriesIndex) {
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

    void updateEventFields(Event event, EventUpdateRequest requestDto) {
        event.setTitle(requestDto.title());
        event.setDescription(requestDto.description());
        event.setStart(requestDto.start());
        event.setDurationMinutes(requestDto.durationMinutes());
        event.setRrule(requestDto.rrule());
        event.setMaxParticipants(requestDto.maxParticipants());
        event.setInstructor(requestDto.instructorId() != null ? userLookupService.findUserById(requestDto.instructorId()) : null);
    }
}
