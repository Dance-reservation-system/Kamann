package pl.kamann.domain.event;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.event.dto.*;
import pl.kamann.domain.event.exception.EventCodes;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;
import pl.kamann.domain.appuser.UserLookupService;

@Service
@RequiredArgsConstructor
public class ClientEventService {
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final OccurrenceEventMapper occurrenceEventMapper;

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;

    private final UserLookupService userLookupService;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;
    private final EventLookupService eventLookupService;

    @Cacheable(value = "occurrencesLight", key = "#scope + '-' + #page + '-' + #size")
    public PaginatedResponseDto<OccurrenceEventLightDto> getOccurrences(OccurrenceEventScope scope, int page, int size) {
        if (scope == null) {
            scope = OccurrenceEventScope.UPCOMING;
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);

        AppUser loggedInUser = userLookupService.getLoggedInUser();

        Page<OccurrenceEvent> pagedOccurrences = occurrenceEventRepository.findFilteredOccurrences(
                scope.name(), loggedInUser, pageable);

        return paginationUtil.toPaginatedResponse(pagedOccurrences, occurrenceEventMapper::toOccurrenceEventLightDto);
    }

    @Cacheable(value = "eventsLight", key = "#page + '-' + #size")
    public PaginatedResponseDto<EventLightDto> getLightEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);
        Page<Event> pagedEvents = eventRepository.findAll(pageable);

        return paginationUtil.toPaginatedResponse(pagedEvents, eventMapper::toEventLightDto);
    }

    @Cacheable(value = "events", key = "#eventType + '-' +  #page + '-' + #size")
    public PaginatedResponseDto<EventDto> getEventsByType(String eventType, int page, int size) {
        String capitalizedEventType = eventType.substring(0, 1).toUpperCase() + eventType.substring(1).toLowerCase();
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);

        Page<Event> pagedEvent = eventRepository.findAllByEventTypeName(capitalizedEventType, pageable);
        return paginationUtil.toPaginatedResponse(pagedEvent, eventMapper::toEventDto);
    }

    @Cacheable(value = "occurrences", key = "#occurrenceId")
    public OccurrenceEventDto getOccurrenceById(Long occurrenceId) {
        OccurrenceEvent occurrenceEvent = occurrenceEventRepository.findById(occurrenceId)
                .orElseThrow(() -> new ApiException(
                        "OccurrenceEvent not found with ID: " + occurrenceId,
                        HttpStatus.BAD_REQUEST,
                        EventCodes.OCCURRENCE_NOT_FOUND.name()));

        return occurrenceEventMapper.toOccurrenceEventDto(occurrenceEvent);
    }

    @Cacheable(value = "events", key = "#eventId")
    public EventDto getEventById(Long eventId) {
        Event event = eventLookupService.findEventById(eventId);

        return eventMapper.toEventDto(event);
    }
}