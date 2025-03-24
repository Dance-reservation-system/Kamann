package pl.kamann.services.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.specific.EventNotFoundException;
import pl.kamann.config.exception.specific.IllegalDateRangeException;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.dtos.event.EventUpdateResponse;
import pl.kamann.dtos.event.OccurrenceEventRangeUpdateRequest;
import pl.kamann.dtos.event.OccurrenceEventUpdateResponse;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.EventRepository;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.services.EventValidationService;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AdminOccurrenceEventServiceTest {

    private final String NEW_TITLE = "New Title";
    private final String OLD_TITLE = "Old Title";
    private final String FIXED_TIME = "2024-01-15T13:00:02";

    @Mock
    EventValidationService eventValidationService;
    @Mock
    OccurrenceEventRepository occurrenceEventRepository;
    @Mock
    EventMapper eventMapper;
    @Mock
    EventRepository eventRepository;
    @InjectMocks
    AdminOccurrenceEventService adminOccurrenceEventService;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void updateOccurrenceEventByOccurrenceEventId_ShouldUpdateOccurrenceEvent_WhenOccurrenceEventExists() {
        //given
        Event event = getExampleEvent();
        OccurrenceEvent occurrenceEvent = getExampleOccurrenceEvent(event);

        EventUpdateRequest request = getExampleEventUpdateRequest();
        EventUpdateResponse eventUpdateResponse = getExampleEventUpdateResponse(event);

        Long eventId = event.getId();
        Long occurrenceEventId = occurrenceEvent.getId();

        when(occurrenceEventRepository.findById(eventId)).thenReturn(Optional.of(occurrenceEvent));
        when(eventMapper.toEventUpdateResponse(eq(event))).thenReturn(eventUpdateResponse);

        //when
        var response = adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(occurrenceEventId, request);

        //then
        assertAll(() -> assertThat(response.affectedOccurrenceEvents()).isEqualTo(1), () -> assertThat(response.responses()).hasSize(1), () -> assertThat(response.responses()
                .getFirst()
                .title()).isEqualTo(NEW_TITLE));
    }

    @Test
    public void updateOccurrenceEventByOccurrenceEventId_ShouldThrowException_WhenEventNotExists() {
        // given
        Long id = 1L;
        EventUpdateRequest eventUpdateRequest = Mockito.mock(EventUpdateRequest.class);
        when(occurrenceEventRepository.findById(id)).thenReturn(Optional.empty());

        // when & then
        assertThrows(ApiException.class, () -> adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(id, eventUpdateRequest));
    }


    @Test
    void updateFutureOccurrenceEvents_ShouldUpdateFutureOccurrenceEvents_WhenEventExists() {
        // given
        Event event = getExampleEvent();

        Long eventId = event.getId();

        OccurrenceEvent occurrenceEventInPast = getExampleOccurrenceEvent(event);
        occurrenceEventInPast.setStart(LocalDateTime.now()
                .minusDays(1));

        OccurrenceEvent occurrenceEventInFuture = getExampleOccurrenceEvent(event);
        occurrenceEventInFuture.setStart(LocalDateTime.now()
                .plusDays(1));

        EventUpdateRequest request = getExampleEventUpdateRequest();

        EventUpdateResponse eventUpdateResponse = getExampleEventUpdateResponse(event);

        List<OccurrenceEvent> occurrenceEventsInFuture = List.of(occurrenceEventInFuture);

        when(occurrenceEventRepository.findAllByEvent_IdAndStartAfter(eq(eventId), any())).thenReturn(occurrenceEventsInFuture);
        when(occurrenceEventRepository.saveAll(occurrenceEventsInFuture)).thenReturn(occurrenceEventsInFuture);
        doNothing().when(eventValidationService)
                .validateUpdate(eq(request), eq(event));
        when(eventMapper.toEventUpdateResponse(eq(event))).thenReturn(eventUpdateResponse);
        when(eventRepository.findById(eventId)).thenReturn(Optional.of(event));

        // when
        OccurrenceEventUpdateResponse response = adminOccurrenceEventService.updateFutureOccurrenceEvents(eventId, request);

        //then
        assertAll(() -> assertThat(response.affectedOccurrenceEvents()).isEqualTo(1), () -> assertThat(response.responses()).hasSize(1), () -> assertThat(response.responses()
                .getFirst()
                .title()).isEqualTo(NEW_TITLE));
    }

    @Test
    void updateFutureOccurrenceEvents_ShouldThrowException_WhenEventNotExists() {
        //given
        Long eventId = 1L;
        EventUpdateRequest eventUpdateRequest = mock(EventUpdateRequest.class);
        when(eventRepository.findById(eq(eventId))).thenReturn(Optional.empty());

        //when & then
        assertThrows(EventNotFoundException.class, () -> adminOccurrenceEventService.updateFutureOccurrenceEvents(eventId, eventUpdateRequest));
    }

    @Test
    void updateAllOccurrenceEvents_ShouldUpdateAllOccurrenceEvents_WhenEventExists() {
        // given
        Event event = getExampleEvent();

        Long eventId = event.getId();

        OccurrenceEvent occurrenceEventInPast = getExampleOccurrenceEvent(event);
        occurrenceEventInPast.setStart(LocalDateTime.now()
                .minusDays(1));

        OccurrenceEvent occurrenceEventInFuture = getExampleOccurrenceEvent(event);
        occurrenceEventInFuture.setStart(LocalDateTime.now()
                .plusDays(1));

        EventUpdateRequest request = getExampleEventUpdateRequest();

        EventUpdateResponse eventUpdateResponse = getExampleEventUpdateResponse(event);

        List<OccurrenceEvent> allOccurrenceEvents = List.of(occurrenceEventInPast, occurrenceEventInFuture);

        when(occurrenceEventRepository.findAllByEvent_Id(eq(eventId))).thenReturn(allOccurrenceEvents);
        when(occurrenceEventRepository.saveAll(allOccurrenceEvents)).thenReturn(allOccurrenceEvents);
        doNothing().when(eventValidationService)
                .validateUpdate(eq(request), any(Event.class));
        when(eventMapper.toEventUpdateResponse(any(Event.class))).thenReturn(eventUpdateResponse);
        when(eventRepository.findById(eventId)).thenReturn(Optional.of(event));

        // when
        OccurrenceEventUpdateResponse response = adminOccurrenceEventService.updateAllOccurrenceEvents(eventId, request);

        //then
        assertThat(response.affectedOccurrenceEvents()).isEqualTo(2);
        assertThat(response.responses()).hasSize(2);
        assertThat(response.responses()
                .get(0)
                .title()).isEqualTo("New Title");
        assertThat(response.responses()
                .get(1)
                .title()).isEqualTo("New Title");
    }

    @Test
    void updateAllOccurrenceEvents_ShouldThrowException_WhenEventNotExists() {
        //given
        Long eventId = 1L;
        EventUpdateRequest eventUpdateRequest = mock(EventUpdateRequest.class);
        when(eventRepository.findById(eq(eventId))).thenReturn(Optional.empty());

        //when & then
        assertThrows(EventNotFoundException.class, () -> adminOccurrenceEventService.updateFutureOccurrenceEvents(eventId, eventUpdateRequest));
    }

    @Test
    void updateRangeOccurrenceEvents_ShouldUpdateOccurrenceEventsInDateRange_WhenEventExistsAndIsInDateRange() {
        // given
        LocalDateTime fixedTestTime = LocalDateTime.parse(FIXED_TIME);

        LocalDateTime startAfter = fixedTestTime.minusHours(1);
        LocalDateTime endBefore = fixedTestTime.plusHours(1);

        Event event = getExampleEvent();
        Long eventId = event.getId();

        OccurrenceEvent occurrenceEvent = getExampleOccurrenceEvent(event);
        occurrenceEvent.setStart(fixedTestTime);

        EventUpdateRequest request = getExampleEventUpdateRequest();

        EventUpdateResponse eventUpdateResponse = getExampleEventUpdateResponse(event);

        OccurrenceEventRangeUpdateRequest rangeUpdateRequest = new OccurrenceEventRangeUpdateRequest(eventId, request, startAfter, endBefore);
        List<OccurrenceEvent> occurrenceEvents = List.of(occurrenceEvent);

        when(eventRepository.findById(eventId)).thenReturn(Optional.of(event));
        doNothing().when(eventValidationService)
                .validateUpdate(eq(request), eq(event));
        when(occurrenceEventRepository.findAllByEvent_IdAndStartAfterAndStartBefore(eq(eventId), eq(startAfter), eq(endBefore))).thenReturn(occurrenceEvents);
        when(occurrenceEventRepository.saveAll(eq(occurrenceEvents))).thenAnswer(invocation -> invocation.getArgument(0));
        when(eventMapper.toEventUpdateResponse(eq(event))).thenReturn(eventUpdateResponse);

        // when
        OccurrenceEventUpdateResponse response = adminOccurrenceEventService.updateRangeOccurrenceEvents(eventId, rangeUpdateRequest);

        // then
        assertAll(() -> verify(occurrenceEventRepository).findAllByEvent_IdAndStartAfterAndStartBefore(eq(eventId), eq(startAfter), eq(endBefore)), () -> assertThat(response.responses()
                .getFirst()
                .title()).isEqualTo(NEW_TITLE));
    }

    @Test
    void updateRangeOccurrenceEvents_ShouldNotUpdateOccurrenceEventsInDateRange_WhenEventExistsAndIsNotInDateRange() {
        // given
        LocalDateTime fixedTestTime = LocalDateTime.parse(FIXED_TIME);

        LocalDateTime startAfter = fixedTestTime.plusHours(1);
        LocalDateTime endBefore = fixedTestTime.plusHours(2);

        Event event = getExampleEvent();
        Long eventId = event.getId();

        OccurrenceEvent occurrenceEvent = getExampleOccurrenceEvent(event);
        occurrenceEvent.setStart(fixedTestTime);

        EventUpdateRequest request = getExampleEventUpdateRequest();

        EventUpdateResponse eventUpdateResponse = getExampleEventUpdateResponse(event);

        OccurrenceEventRangeUpdateRequest rangeUpdateRequest = new OccurrenceEventRangeUpdateRequest(eventId, request, startAfter, endBefore);
        List<OccurrenceEvent> occurrenceEvents = List.of(occurrenceEvent);

        when(eventRepository.findById(eventId)).thenReturn(Optional.of(event));
        doNothing().when(eventValidationService)
                .validateUpdate(eq(request), eq(event));
        when(occurrenceEventRepository.findAllByEvent_IdAndStartAfterAndStartBefore(eq(eventId), eq(startAfter), eq(endBefore))).thenReturn(emptyList());
        when(occurrenceEventRepository.saveAll(eq(occurrenceEvents))).thenAnswer(invocation -> invocation.getArgument(0));
        when(eventMapper.toEventUpdateResponse(eq(event))).thenReturn(eventUpdateResponse);

        // when
        OccurrenceEventUpdateResponse response = adminOccurrenceEventService.updateRangeOccurrenceEvents(eventId, rangeUpdateRequest);

        // then
        assertAll(() -> verify(occurrenceEventRepository).findAllByEvent_IdAndStartAfterAndStartBefore(eq(eventId), eq(startAfter), eq(endBefore)), () -> assertThat(response.responses()
                .size()).isEqualTo(0), () -> assertThat(event.getTitle()).isEqualTo(OLD_TITLE), () -> assertThat(occurrenceEvent.getEvent()
                .getTitle()).isEqualTo(OLD_TITLE));
    }

    @Test
    void updateRangeOccurrenceEvents_ShouldThrowException_WhenDateRangeIsInvalid() {
        //given
        LocalDateTime fixedTestTime = LocalDateTime.parse(FIXED_TIME);
        LocalDateTime startAfter = fixedTestTime.plusHours(2);
        LocalDateTime endBefore = fixedTestTime.minusHours(2);

        Event event = getExampleEvent();
        Long eventId = event.getId();

        OccurrenceEvent occurrenceEvent = getExampleOccurrenceEvent(event);
        occurrenceEvent.setStart(fixedTestTime);

        EventUpdateRequest request = getExampleEventUpdateRequest();

        OccurrenceEventRangeUpdateRequest rangeUpdateRequest = new OccurrenceEventRangeUpdateRequest(eventId, request, startAfter, endBefore);

        //when & then
        assertThrows(IllegalDateRangeException.class, () -> adminOccurrenceEventService.updateRangeOccurrenceEvents(eventId, rangeUpdateRequest));
    }

    private Event getExampleEvent() {
        Long eventId = 1L;
        Event event = new Event();
        event.setId(eventId);
        event.setTitle("Old Title");
        return event;
    }

    private OccurrenceEvent getExampleOccurrenceEvent(Event event) {
        Long occurrenceEventId = 1L;
        OccurrenceEvent occurrenceEvent = new OccurrenceEvent();
        occurrenceEvent.setId(occurrenceEventId);
        occurrenceEvent.setEvent(event);
        return occurrenceEvent;
    }

    EventUpdateRequest getExampleEventUpdateRequest() {
        return new EventUpdateRequest(NEW_TITLE, null, null, null, null, null, 0);
    }

    EventUpdateResponse getExampleEventUpdateResponse(Event event) {
        return new EventUpdateResponse(event.getId(), NEW_TITLE, event.getDescription(), event.getStart(), event.getDurationMinutes(), event.getStatus(), event.getUpdatedAt(), 0L, event.getMaxParticipants());
    }
}