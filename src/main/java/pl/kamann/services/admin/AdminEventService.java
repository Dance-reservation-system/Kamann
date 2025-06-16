package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.dmfs.rfc5545.DateTime;
import org.dmfs.rfc5545.recur.RecurrenceRule;
import org.dmfs.rfc5545.recur.RecurrenceRuleIterator;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.services.EventLookupService;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.config.pagination.PaginatedResponseDto;
import pl.kamann.config.pagination.PaginationService;
import pl.kamann.config.pagination.PaginationUtil;
import pl.kamann.dtos.event.*;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEventStatus;
import pl.kamann.entities.event.SchedulingStatus;
import pl.kamann.entities.event.EventType;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.EventRepository;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.services.EventTypeService;
import pl.kamann.services.EventValidationService;
import pl.kamann.services.NotificationService;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminEventService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final EventTypeService eventTypeService;
    private final EventValidationService eventValidationService;

    private final OccurrenceEventRepository occurrenceEventRepository;

    private final NotificationService notificationService;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;

    private final UserLookupService userLookupService;
    private final EventLookupService eventLookupService;

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public CreateEventResponse createEvent(CreateEventRequest request) {
        eventValidationService.validateCreate(request);

        Event event = eventMapper.toEvent(request, userLookupService);

        event.setCreatedBy(userLookupService.findUserById(request.createdById()));

        EventType eventType = eventTypeService.findOrCreateEventType(request.eventTypeName());
        event.setEventType(eventType);

        event = eventRepository.save(event);

        occurrenceEventRepository.saveAll(generateOccurrences(event));

        return eventMapper.toCreateEventResponse(event);
    }

    @Cacheable(value = "events", key = "#page + '-' + #size")
    public PaginatedResponseDto<EventDto> listEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);

        Page<Event> pagedEvents = eventRepository.findAll(pageable);

        return paginationUtil.toPaginatedResponse(pagedEvents, eventMapper::toEventDto);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public EventUpdateResponse updateEvent(Long id, EventUpdateRequest requestDto) {
        Event event = eventLookupService.findEventById(id);

        eventValidationService.validateUpdate(requestDto, event);

        updateEventFields(event, requestDto);
        eventRepository.save(event);

        return eventMapper.toEventUpdateResponse(event);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public void deleteEvent(Long id, boolean force) {
        Event event = eventLookupService.findEventById(id);

        if (!force && occurrenceEventRepository.existsByEvent(event)) {
            throw new ApiException("Cannot delete event with occurrences unless forced",
                    HttpStatus.BAD_REQUEST, EventCodes.EVENT_HAS_OCCURRENCES.name());
        }

        occurrenceEventRepository.deleteByEvent(event);
        eventRepository.delete(event);
    }

    @Transactional
    @CacheEvict(value = {"events", "eventsLight", "occurrences", "occurrencesLight"}, allEntries = true)
    public void cancelEvent(Long id, SchedulingStatus schedulingStatus) {
        Event event = eventLookupService.findEventById(id);
        LocalDateTime now = LocalDateTime.now();

        if (event.getSchedulingStatus() == SchedulingStatus.COMPLETED) {
            throw new ApiException("Event is already canceled.",
                    HttpStatus.BAD_REQUEST,
                    EventCodes.EVENT_ALREADY_CANCELED.name());
        }

        event.setSchedulingStatus(schedulingStatus);
        event.setUpdatedAt(LocalDateTime.now());

        List<OccurrenceEvent> futureOccurrences = occurrenceEventRepository.findByEventAndMeetingDateAfter(event, now);
        futureOccurrences.forEach(occ -> {
            occ.setOccurrenceEventStatus(OccurrenceEventStatus.CANCELED);
        });

        event.setSchedulingStatus(SchedulingStatus.COMPLETED);

        eventRepository.save(event);
        occurrenceEventRepository.saveAll(futureOccurrences);

        notificationService.notifyParticipants(event);
    }

    private void updateEventFields(Event event, EventUpdateRequest requestDto) {
        event.setTitle(requestDto.title());
        event.setDescription(requestDto.description());
        event.setReleaseDate(requestDto.start());
        event.setDurationMinutes(requestDto.durationMinutes());
        event.setRrule(requestDto.rrule());
        event.setMaxParticipants(requestDto.maxParticipants());
        event.setInstructor(requestDto.instructorId() != null ? userLookupService.findUserById(requestDto.instructorId()) : null);
    }

    public List<OccurrenceEvent> generateOccurrences(Event event) {
        List<OccurrenceEvent> occurrences = new ArrayList<>();

        // If no RRULE is provided, create a single occurrence (one-time event)
        if (event.getRrule() == null || event.getRrule().isEmpty()) {
            occurrences.add(createOccurrence(event, event.getReleaseDate(), 0));
            return occurrences;
        }

        try {
            RecurrenceRule rule = new RecurrenceRule(event.getRrule());
            DateTime dtStart = new DateTime(
                    event.getReleaseDate().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
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

    private OccurrenceEvent createOccurrence(Event event, LocalDateTime start, int seriesIndex) {
        return OccurrenceEvent.builder()
                .event(event)
                .meetingDate(start)
                .createdBy(event.getCreatedBy())
                .instructor(event.getInstructor())
                .seriesIndex(seriesIndex)
                .occurrenceEventStatus(OccurrenceEventStatus.UPCOMING)
                .build();
    }

    @Cacheable(value = "events", key = "#eventId")
    public EventDto getEventDtoById(Long eventId) {
        Event event = eventLookupService.findEventById(eventId);

        return eventMapper.toEventDto(event);
    }
}