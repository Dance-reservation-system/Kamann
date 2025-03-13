package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AttendanceCodes;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.EventRepository;
import pl.kamann.repositories.OccurrenceEventRepository;

@RequiredArgsConstructor
@Service
public class EventLookupService {

    private final EventRepository eventRepository;
    private final OccurrenceEventRepository occurrenceEventRepository;

    public OccurrenceEvent findOccurrenceEventByOccurrenceEventId(Long occurrenceEventId) {
        return occurrenceEventRepository.findById(occurrenceEventId)
                .orElseThrow(() -> new ApiException(
                        "OccurrenceEvent not found for ID: " + occurrenceEventId,
                        HttpStatus.NOT_FOUND,
                        AttendanceCodes.OCCURRENCE_EVENT_NOT_FOUND.name()
                ));
    }

    public Event findEventById(Long eventId) {
        return eventRepository.findById(eventId)
                .orElseThrow(() -> new ApiException(
                        "Event not found with ID: " + eventId,
                        HttpStatus.NOT_FOUND,
                        EventCodes.EVENT_NOT_FOUND.name()
                ));
    }
}
