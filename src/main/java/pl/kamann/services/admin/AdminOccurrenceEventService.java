package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.config.exception.specific.EventNotFoundException;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.dtos.event.EventUpdateResponse;
import pl.kamann.dtos.event.OccurrenceEventRangeUpdateRequest;
import pl.kamann.dtos.event.OccurrenceEventUpdateResponse;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventStatus;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.EventRepository;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.services.EventValidationService;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminOccurrenceEventService {

    private final EventValidationService eventValidationService;
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final UserLookupService userLookupService;

    public void saveOccurrenceEvent(OccurrenceEvent occurrenceEvent) {
        occurrenceEventRepository.save(occurrenceEvent);
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateOccurrenceEventByOccurrenceEventId(Long occurrenceEventId, EventUpdateRequest requestDto) {
        OccurrenceEvent occurrenceEvent = occurrenceEventRepository.findById(occurrenceEventId)
                .orElseThrow(() -> new ApiException("Occurrence not found with ID: " + occurrenceEventId, HttpStatus.BAD_REQUEST, EventCodes.OCCURRENCE_NOT_FOUND.name()));

        eventValidationService.validateUpdate(requestDto, occurrenceEvent.getEvent());

        updateEventFields(occurrenceEvent.getEvent(), requestDto);
        occurrenceEventRepository.save(occurrenceEvent);
        EventUpdateResponse eventUpdateResponse = eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent());
        return new OccurrenceEventUpdateResponse(1, List.of(eventUpdateResponse));
    }
    @Transactional
    public OccurrenceEventUpdateResponse updateFutureOccurrenceEvents(Long eventId, EventUpdateRequest requestDto) {
        if (eventExists(eventId)) {
            List<OccurrenceEvent> futureOccurrences = occurrenceEventRepository.findAllByEvent_IdAndStartAfter(eventId, LocalDateTime.now());
            validateAndUpdateOccurrenceEvents(futureOccurrences, requestDto);

            List<EventUpdateResponse> eventUpdateResponses = persistAndMapOccurrenceEvents(futureOccurrences);
            return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
        } else {
            throw new EventNotFoundException();
        }
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateAllOccurrenceEvents(Long eventId, EventUpdateRequest requestDto) {
        if (eventExists(eventId)) {
            List<OccurrenceEvent> allByEventId = occurrenceEventRepository.findAllByEvent_Id(eventId);
            validateAndUpdateOccurrenceEvents(allByEventId, requestDto);

            List<EventUpdateResponse> eventUpdateResponses = persistAndMapOccurrenceEvents(allByEventId);
            return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
        } else {
            throw new EventNotFoundException();
        }
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateRangeOccurrenceEvents(Long eventId, OccurrenceEventRangeUpdateRequest requestDto) {
        if(eventExists(eventId)) {
            List<OccurrenceEvent> allByEventIdAndStartBetween = occurrenceEventRepository.findAllByEvent_IdAndStartAfterAndStartBefore(
                    eventId,
                    requestDto.startAfter(),
                    requestDto.endBefore());
            validateAndUpdateOccurrenceEvents(allByEventIdAndStartBetween, requestDto.eventUpdateRequestDto());

            List<EventUpdateResponse> eventUpdateResponses = persistAndMapOccurrenceEvents(allByEventIdAndStartBetween);
            return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
        } else {
            throw new EventNotFoundException();
        }
    }

    @Transactional
    public void cancelOccurrenceEventsAfter(Event event, LocalDateTime date) {
        List<OccurrenceEvent> futureOccurrences = occurrenceEventRepository.findByEventAndStartAfter(event, date);
        futureOccurrences.forEach(occ -> {
            occ.setCanceled(true);
            occ.setEventStatus(EventStatus.CANCELED);
        });
    }

    public void deleteOccurrenceEvent(Event event) {
        occurrenceEventRepository.deleteByEvent(event);
    }

    public boolean hasOccurrenceEvents(Event event) {
        return occurrenceEventRepository.existsByEvent(event);
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

    private void validateAndUpdateOccurrenceEvents(List<OccurrenceEvent> occurrenceEvents, EventUpdateRequest requestDto) {
        occurrenceEvents.stream()
                .map(OccurrenceEvent::getEvent)
                .forEach(event -> {
                    eventValidationService.validateUpdate(requestDto, event);
                    updateEventFields(event, requestDto);
                });
    }

    private List<EventUpdateResponse> persistAndMapOccurrenceEvents(List<OccurrenceEvent> occurrenceEvents) {
        List<OccurrenceEvent> savedOccurrenceEvents = occurrenceEventRepository.saveAll(occurrenceEvents);
        return savedOccurrenceEvents.stream()
                .map(occurrenceEvent -> eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent()))
                .toList();
    }

    private boolean eventExists(Long eventId) {
        return eventRepository.findById(eventId).isPresent();
    }
}
