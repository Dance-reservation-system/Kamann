package pl.kamann.services.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.specific.EventNotFoundException;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.dtos.event.EventUpdateResponse;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminOccurrenceEventServiceTest {

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
    public void updateOccurrenceEventByOccurrenceEventId_ShouldThrowException_WhenEventNotFound() {
        //given
        Long id = 1L;
        EventUpdateRequest eventUpdateRequest = Mockito.mock(EventUpdateRequest.class);
        when(occurrenceEventRepository.findById(any())).thenReturn(Optional.empty());

        //when & then
        assertThrows(ApiException.class, () -> adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(id, eventUpdateRequest));
    }

    @Test
    public void updateOccurrenceEventByOccurrenceEventId_ShouldUpdateOccurrenceEvent_WhenOccurrenceEventExists() {
        //given
        Event event = new Event();
        event.setTitle("Old Title");

        Long occurrenceEventId = 1L;
        OccurrenceEvent occurrenceEvent = new OccurrenceEvent();
        occurrenceEvent.setId(occurrenceEventId);
        occurrenceEvent.setEvent(event);
        EventUpdateRequest request = new EventUpdateRequest("New Title",  // title
                null,         // description
                null,         // start
                null,         // durationMinutes
                null,         // rrule
                null,         // instructorId
                0          // maxParticipants
        );

        EventUpdateResponse eventUpdateResponse = new EventUpdateResponse(occurrenceEvent.getEvent()
                .getId(), "New Title", occurrenceEvent.getEvent()
                .getDescription(), occurrenceEvent.getEvent()
                .getStart(), occurrenceEvent.getEvent()
                .getDurationMinutes(), occurrenceEvent.getEvent()
                .getStatus(), occurrenceEvent.getEvent()
                .getUpdatedAt(), 0L, occurrenceEvent.getEvent()
                .getMaxParticipants());

        when(occurrenceEventRepository.findById(occurrenceEventId)).thenReturn(Optional.of(occurrenceEvent));
        when(eventMapper.toEventUpdateResponse(any(Event.class))).thenReturn(eventUpdateResponse);

        //when
        OccurrenceEventUpdateResponse occurrenceEventUpdateResponse = adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(occurrenceEventId, request);

        //then
        assertThat(occurrenceEvent.getEvent()
                .getTitle()).isEqualTo("New Title");
        assertThat(occurrenceEventUpdateResponse.affectedOccurrenceEvents()).isEqualTo(1);
        assertThat(occurrenceEventUpdateResponse.responses()
                .getFirst()
                .title()).isEqualTo("New Title");
    }


    @Test
    void updateFutureOccurrenceEvents_ShouldUpdateFutureOccurrenceEvents_WhenEventIdExists() {
        // given
        Long eventId = 1L;
        Event event = new Event();
        event.setId(eventId);
        event.setTitle("Old Title");

        OccurrenceEvent occurrenceEventInFuture = new OccurrenceEvent();
        occurrenceEventInFuture.setEvent(event);
        occurrenceEventInFuture.setStart(LocalDateTime.now()
                .plusDays(1));

        List<OccurrenceEvent> futureOccurrences = List.of(occurrenceEventInFuture);

        EventUpdateRequest request = new EventUpdateRequest("New Title",  // title
                null,         // description
                null,         // start
                null,         // durationMinutes
                null,         // rrule
                null,         // instructorId
                0             // maxParticipants
        );

        EventUpdateResponse eventUpdateResponse = new EventUpdateResponse(eventId, "New Title", null, null, null, null, null, 0L, 0);

        when(occurrenceEventRepository.findAllByEvent_IdAndStartAfter(eq(eventId), any(LocalDateTime.class))).thenReturn(futureOccurrences);
        when(occurrenceEventRepository.saveAll(futureOccurrences)).thenReturn(futureOccurrences);
        doNothing().when(eventValidationService)
                .validateUpdate(eq(request), any(Event.class));
        when(eventMapper.toEventUpdateResponse(any(Event.class))).thenReturn(eventUpdateResponse);
        when(eventRepository.findById(eventId)).thenReturn(Optional.of(event));

        // when
        OccurrenceEventUpdateResponse response = adminOccurrenceEventService.updateFutureOccurrenceEvents(eventId, request);

        //then
        assertThat(response.affectedOccurrenceEvents()).isEqualTo(1);
        assertThat(response.responses()).hasSize(1);
        assertThat(response.responses()
                .getFirst()
                .title()).isEqualTo("New Title");
    }

    @Test
    void updateFutureOccurrenceEvents_ShouldThrowEventNotFoundException_WhenEventNotFound() {
        //given
        Long eventId = 1L;
        EventUpdateRequest eventUpdateRequest = mock(EventUpdateRequest.class);
        when(eventRepository.findById(eq(eventId))).thenReturn(Optional.empty());

        //when & then
        assertThrows(EventNotFoundException.class, () -> {
            adminOccurrenceEventService.updateFutureOccurrenceEvents(eventId, eventUpdateRequest);
        });
    }

    @Test
    void updateAllOccurrenceEvents_ShouldUpdateAllOccurrenceEvents_WhenEventExists() {

    }
}