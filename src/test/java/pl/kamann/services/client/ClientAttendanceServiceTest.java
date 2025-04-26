package pl.kamann.services.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.attendance.AttendanceRepository;
import pl.kamann.domain.attendance.AttendanceStatus;
import pl.kamann.domain.attendance.ClientAttendanceService;
import pl.kamann.domain.event.Event;
import pl.kamann.domain.event.EventLookupService;
import pl.kamann.domain.event.OccurrenceEvent;
import pl.kamann.domain.membershipcard.ClientMembershipCardService;
import pl.kamann.infrastructure.handler.ApiException;

import java.lang.reflect.Field;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class ClientAttendanceServiceTest {

    private ClientAttendanceService attendanceService;
    private OccurrenceEvent testOccurrence;

    @BeforeEach
    void setup() throws Exception {
        MockitoAnnotations.openMocks(this);
        AttendanceRepository attendanceRepository = mock(AttendanceRepository.class);
        ClientMembershipCardService clientMembershipCardService = mock(ClientMembershipCardService.class);
        EventLookupService eventLookupService = mock(EventLookupService.class);
        UserLookupService userLookupService = mock(UserLookupService.class);

        attendanceService = new ClientAttendanceService(
                attendanceRepository,
                clientMembershipCardService,
                null,
                eventLookupService,
                userLookupService
        );

        Event event = mock(Event.class);
        AppUser createdBy = mock(AppUser.class);

        testOccurrence = OccurrenceEvent.create(
                event,
                LocalDateTime.now().plusHours(2),
                createdBy
        );
    }

    @Test
    void determineCancellationStatus_shouldReturnEarlyCancel() throws Exception {
        setStartTo(testOccurrence, LocalDateTime.now().plusHours(48));
        AttendanceStatus status = attendanceService.determineCancellationStatus(testOccurrence);
        assertEquals(AttendanceStatus.EARLY_CANCEL, status, "Expected EARLY_CANCEL for event > 24 hours away");
    }

    @Test
    void determineCancellationStatus_shouldReturnLateCancel() throws Exception {
        setStartTo(testOccurrence, LocalDateTime.now().plusHours(23));
        AttendanceStatus status = attendanceService.determineCancellationStatus(testOccurrence);
        assertEquals(AttendanceStatus.LATE_CANCEL, status, "Expected LATE_CANCEL for event < 24 hours away");
    }

    @Test
    void validateCancellation_shouldThrowException_whenOccurrenceStarted() throws Exception {
        setStartTo(testOccurrence, LocalDateTime.now().minusHours(1));
        ApiException ex = assertThrows(ApiException.class, () ->
                        attendanceService.validateCancellation(testOccurrence),
                "Expected ApiException for past event"
        );
        assertEquals("Cannot cancel an occurrence that has already started", ex.getMessage(), "Exception message mismatch");
    }

    void setStartTo(OccurrenceEvent event, LocalDateTime start) throws Exception {
        Field field = OccurrenceEvent.class.getDeclaredField("start");
        field.setAccessible(true);
        field.set(event, start);
    }
}
