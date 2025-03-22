package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.pagination.PaginatedResponseDto;
import pl.kamann.dtos.event.*;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventStatus;
import pl.kamann.entities.event.EventType;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.EventRepository;
import pl.kamann.services.EventTypeService;
import pl.kamann.services.EventValidationService;
import pl.kamann.services.NotificationService;
import pl.kamann.config.pagination.PaginationService;
import pl.kamann.config.pagination.PaginationUtil;
import pl.kamann.config.exception.services.EventLookupService;
import pl.kamann.config.exception.services.UserLookupService;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AdminEventService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final EventTypeService eventTypeService;
    private final EventValidationService eventValidationService;

    private final AdminEventHelperService adminEventHelperService;

    private final NotificationService notificationService;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;

    private final EventLookupService eventLookupService;
    private final UserLookupService userLookupService;


    @Transactional
    public CreateEventResponse createEvent(CreateEventRequest request) {
        eventValidationService.validateCreate(request);

        Event event = eventMapper.toEvent(request, userLookupService);
        event.setCreatedBy(userLookupService.findUserById(request.createdById()));

        EventType eventType = eventTypeService.findOrCreateEventType(request.eventTypeName());
        event.setEventType(eventType);
        event = eventRepository.save(event);

        adminEventHelperService.createOccurrenceEvents(event);

        return eventMapper.toCreateEventResponse(event);
    }

    public PaginatedResponseDto<EventDto> listEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);

        Page<Event> pagedEvents = eventRepository.findAll(pageable);

        return paginationUtil.toPaginatedResponse(pagedEvents, eventMapper::toEventDto);
    }

    @Transactional
    public EventUpdateResponse updateEvent(Long id, EventUpdateRequest requestDto) {
        Event event = eventLookupService.findEventById(id);

        eventValidationService.validateUpdate(requestDto, event);

        adminEventHelperService.updateEventFields(event, requestDto);
        eventRepository.save(event);

        return eventMapper.toEventUpdateResponse(event);
    }

    @Transactional
    public void deleteEvent(Long id, boolean force) {
        Event event = eventLookupService.findEventById(id);
        boolean hasOccurrenceEvents = adminEventHelperService.hasOccurrenceEvents(event);

        if (!force && hasOccurrenceEvents) {
            throw new ApiException("Cannot delete event with occurrences unless forced",
                    HttpStatus.BAD_REQUEST, EventCodes.EVENT_HAS_OCCURRENCES.name());
        }
        adminEventHelperService.deleteOccurrenceEvent(event);
        eventRepository.delete(event);
    }

    @Transactional
    public void cancelEvent(Long id) {
        Event event = eventLookupService.findEventById(id);
        LocalDateTime now = LocalDateTime.now();

        if (event.getStatus() == EventStatus.CANCELED) {
            throw new ApiException("Event is already canceled.",
                    HttpStatus.BAD_REQUEST,
                    EventCodes.EVENT_ALREADY_CANCELED.name());
        }

        event.setStatus(EventStatus.CANCELED);
        event.setUpdatedAt(LocalDateTime.now());

        eventRepository.save(event);
        adminEventHelperService.cancelOccurrenceEventsAfter(event, now);
        notificationService.notifyParticipants(event);
    }

    public EventDto getEventDtoById(Long eventId) {
        Event eventById = eventLookupService.findEventById(eventId);

        return eventMapper.toEventDto(eventById);
    }
}