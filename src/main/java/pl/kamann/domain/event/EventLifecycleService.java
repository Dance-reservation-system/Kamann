package pl.kamann.domain.event;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.auth.GetLoggedInUserService;
import pl.kamann.application.notification.NotificationService;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.event.dto.CreateEventRequest;
import pl.kamann.domain.event.dto.CreateEventResponse;
import pl.kamann.domain.event.dto.EventUpdateRequest;
import pl.kamann.domain.event.dto.EventUpdateResponse;
import pl.kamann.domain.event.exception.EventCodes;
import pl.kamann.infrastructure.handler.ApiException;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class EventLifecycleService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final EventTypeService eventTypeService;
    private final EventValidationService eventValidationService;
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final NotificationService notificationService;
    private final UserLookupService userLookupService;
    private final EventLookupService eventLookupService;
    private final GetLoggedInUserService getLoggedInUserService;
    private final OccurrenceGenerationService occurrenceGenerationService;

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public CreateEventResponse createEvent(CreateEventRequest createEventRequest, HttpServletRequest request) {
        eventValidationService.validateCreate(createEventRequest);
        AppUser loggedInUser = getLoggedInUserService.getLoggedInDomainUser(request);
        Event event = eventMapper.toEvent(createEventRequest, userLookupService, loggedInUser);
        event.setCreatedBy(userLookupService.findUserById(createEventRequest.createdById()));
        event.setEventType(eventTypeService.findOrCreateEventType(createEventRequest.eventTypeName()));
        event = eventRepository.save(event);
        occurrenceEventRepository.saveAll(occurrenceGenerationService.generateOccurrences(event));
        return eventMapper.toCreateEventResponse(event);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public EventUpdateResponse updateEvent(Long id, EventUpdateRequest dto) {
        Event event = eventLookupService.findEventById(id);
        eventValidationService.validateUpdate(dto, event);
        updateEventFields(event, dto);
        eventRepository.save(event);
        return eventMapper.toEventUpdateResponse(event);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public void deleteEvent(Long id, boolean force) {
        Event event = eventLookupService.findEventById(id);
        if (!force && occurrenceEventRepository.existsByEvent(event)) {
            throw new ApiException("Cannot delete event with occurrences unless forced", HttpStatus.BAD_REQUEST, EventCodes.EVENT_HAS_OCCURRENCES.name());
        }
        occurrenceEventRepository.deleteByEvent(event);
        eventRepository.delete(event);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public void cancelEvent(Long id, EventStatus status) {
        Event event = eventLookupService.findEventById(id);
        if (event.getStatus() == EventStatus.CANCELED) {
            throw new ApiException("Event is already canceled", HttpStatus.BAD_REQUEST, EventCodes.EVENT_ALREADY_CANCELED.name());
        }
        event.setStatus(status);
        event.setUpdatedAt(LocalDateTime.now());

        List<OccurrenceEvent> future = occurrenceEventRepository.findByEventAndStartAfter(event, LocalDateTime.now());
        future.forEach(OccurrenceEvent::cancel);

        eventRepository.save(event);
        occurrenceEventRepository.saveAll(future);
        notificationService.notifyParticipants(event);
    }

    private void updateEventFields(Event event, EventUpdateRequest dto) {
        event.setTitle(dto.title());
        event.setDescription(dto.description());
        event.setStart(dto.start());
        event.setDurationMinutes(dto.durationMinutes());
        event.setRrule(dto.rrule());
        event.setMaxParticipants(dto.maxParticipants());
        event.setInstructor(dto.instructorId() != null ? userLookupService.findUserById(dto.instructorId()) : null);
    }
}
