package pl.kamann.domain.event;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.attendance.AttendanceCodes;
import pl.kamann.domain.event.exception.EventCodes;
import pl.kamann.infrastructure.handler.ApiException;

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
