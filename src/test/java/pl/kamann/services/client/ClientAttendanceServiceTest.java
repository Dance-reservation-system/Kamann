package pl.kamann.services.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.attendance.AttendanceStatus;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.AttendanceRepository;
import pl.kamann.config.exception.services.EventLookupService;
import pl.kamann.config.exception.services.UserLookupService;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

public class ClientAttendanceServiceTest {

    private ClientMembershipCardService clientMembershipCardService;
    private ClientAttendanceService attendanceService;

    private OccurrenceEvent testOccurrence;
    private UserLookupService userLookupService;
    private EventLookupService eventLookupService;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
        AttendanceRepository attendanceRepository = mock(AttendanceRepository.class);
        attendanceService = new ClientAttendanceService(attendanceRepository, clientMembershipCardService, eventLookupService, userLookupService);

        testOccurrence = OccurrenceEvent.builder()
                .id(100L)
                .start(LocalDateTime.now().plusHours(2))
                .durationMinutes(60)
                .maxParticipants(10)
                .participants(new java.util.ArrayList<>())
                .build();
    }

    @Test
    public void determineCancellationStatus_shouldReturnEarlyCancel() {
        // Set the occurrence to start in 48 hours so that cancellation is early.
        testOccurrence.setStart(LocalDateTime.now().plusHours(48));
        AttendanceStatus status = attendanceService.determineCancellationStatus(testOccurrence);
        assertEquals(AttendanceStatus.EARLY_CANCEL, status);
    }

    @Test
    public void determineCancellationStatus_shouldReturnLateCancel() {
        // Set occurrence to start in 23 hours, so cancellation deadline is passed.
        testOccurrence.setStart(LocalDateTime.now().plusHours(23));
        AttendanceStatus status = attendanceService.determineCancellationStatus(testOccurrence);
        assertEquals(AttendanceStatus.LATE_CANCEL, status);
    }

    @Test
    public void validateCancellation_shouldThrowException_whenOccurrenceStarted() {
        testOccurrence.setStart(LocalDateTime.now().minusHours(1));
        ApiException ex = assertThrows(ApiException.class, () -> attendanceService.validateCancellation(testOccurrence));
        assertEquals("Cannot cancel an occurrence that has already started", ex.getMessage());
    }
}
