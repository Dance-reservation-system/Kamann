package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.dtos.event.EventUpdateResponse;
import pl.kamann.dtos.event.OccurrenceEventRangeUpdateRequest;
import pl.kamann.dtos.event.OccurrenceEventUpdateResponse;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.services.EventValidationService;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminOccurrenceEventService {
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final EventMapper eventMapper;
    private final EventValidationService eventValidationService;
    private final AdminEventHelperService adminEventHelperService;

    @Transactional
    public OccurrenceEventUpdateResponse updateOccurrenceEventByOccurrenceEventId(Long id, EventUpdateRequest requestDto) {
        OccurrenceEvent occurrenceEvent = occurrenceEventRepository.findById(id)
                .orElseThrow(() -> new ApiException("Occurrence not found with ID: " + id, HttpStatus.BAD_REQUEST, EventCodes.OCCURRENCE_NOT_FOUND.name()));

        eventValidationService.validateUpdate(requestDto, occurrenceEvent.getEvent());

        adminEventHelperService.updateEventFields(occurrenceEvent.getEvent(), requestDto);
        occurrenceEventRepository.save(occurrenceEvent);
        EventUpdateResponse eventUpdateResponse = eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent());
        return new OccurrenceEventUpdateResponse(1, List.of(eventUpdateResponse));
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateFutureOccurrenceEvents(Long id, EventUpdateRequest requestDto) {
        List<OccurrenceEvent> futureOccurrences = occurrenceEventRepository.findAllByEvent_IdAndStartAfter(id, LocalDateTime.now());
        validateAndUpdateOccurrenceEvents(futureOccurrences, requestDto);

        List<OccurrenceEvent> savedOccurrenceEvents = occurrenceEventRepository.saveAll(futureOccurrences);
        List<EventUpdateResponse> eventUpdateResponses = savedOccurrenceEvents.stream()
                .map(occurrenceEvent -> eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent()))
                .toList();

        return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateAllOccurrenceEvents(Long id, EventUpdateRequest requestDto) {
        List<OccurrenceEvent> allByEventId = occurrenceEventRepository.findAllByEvent_Id(id);
        validateAndUpdateOccurrenceEvents(allByEventId, requestDto);

        List<OccurrenceEvent> savedOccurrenceEvents = occurrenceEventRepository.saveAll(allByEventId);
        List<EventUpdateResponse> eventUpdateResponses = savedOccurrenceEvents.stream()
                .map(occurrenceEvent -> eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent()))
                .toList();

        return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
    }

    @Transactional
    public OccurrenceEventUpdateResponse updateRangeOccurrenceEvents(Long id, OccurrenceEventRangeUpdateRequest requestDto) {
        List<OccurrenceEvent> allByEventIdAndWithinDateRange = occurrenceEventRepository.findAllByStartBetween(requestDto.startAfter(), requestDto.endBefore());
        validateAndUpdateOccurrenceEvents(allByEventIdAndWithinDateRange, requestDto.eventUpdateRequestDto());

        List<OccurrenceEvent> savedOccurrenceEvents = occurrenceEventRepository.saveAll(allByEventIdAndWithinDateRange);
        List<EventUpdateResponse> eventUpdateResponses = savedOccurrenceEvents.stream()
                .map(occurrenceEvent -> eventMapper.toEventUpdateResponse(occurrenceEvent.getEvent()))
                .toList();
        return new OccurrenceEventUpdateResponse(eventUpdateResponses.size(), eventUpdateResponses);
    }

    private void validateAndUpdateOccurrenceEvents(List<OccurrenceEvent> occurrenceEvents, EventUpdateRequest requestDto) {
        occurrenceEvents.stream()
                .map(OccurrenceEvent::getEvent)
                .forEach(event -> {
                    eventValidationService.validateUpdate(requestDto, event);
                    adminEventHelperService.updateEventFields(event, requestDto);
                });
    }
}
