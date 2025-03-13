package pl.kamann.services.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.dtos.AttendanceDetailsDto;
import pl.kamann.entities.attendance.Attendance;
import pl.kamann.entities.attendance.AttendanceStatus;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.AttendanceMapper;
import pl.kamann.repositories.AttendanceRepository;
import pl.kamann.config.exception.services.EventLookupService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AdminAttendanceServiceTest {

    @Mock
    private AttendanceRepository attendanceRepository;

    @Mock
    private AttendanceMapper attendanceMapper;

    @Mock
    private EventLookupService eventLookupService;

    @InjectMocks
    private AdminAttendanceService adminAttendanceService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void cancelClientAttendance_ShouldThrowException_WhenNotFound() {
        Long eventId = 1L;
        Long clientId = 2L;

        OccurrenceEvent event = new OccurrenceEvent();

        when(eventLookupService.findOccurrenceEventByOccurrenceEventId(eventId)).thenReturn(event);

        ApiException exception = assertThrows(ApiException.class,
                () -> adminAttendanceService.cancelClientAttendance(eventId, clientId));

        assertEquals("Attendance not found for event and client", exception.getMessage());
        verify(attendanceRepository, never()).delete(any());
    }

    @Test
    void markAttendance_ShouldThrowException_WhenNotFound() {
        var eventId = 1L;
        var clientId = 2L;

        var event = new Event();

        when(eventLookupService.findEventById(eventId)).thenReturn(event);

        ApiException exception = assertThrows(ApiException.class,
                () -> adminAttendanceService.markAttendance(eventId, clientId, AttendanceStatus.PRESENT));

        assertEquals("Attendance not found for event and client", exception.getMessage());
        verify(attendanceRepository, never()).save(any());
    }


    @Test
    void getAttendanceSummary_ShouldReturnSummary() {
        var pageable = Pageable.unpaged();

        var attendance = new Attendance();
        var dto = AttendanceDetailsDto.builder()
                .id(1L)
                .userId(100L)
                .status(AttendanceStatus.PRESENT)
                .build();
        Page<Attendance> attendancePage = new PageImpl<>(List.of(attendance));

        when(attendanceRepository.findAll(pageable)).thenReturn(attendancePage);
        when(attendanceMapper.toAttendanceDetailsDto(attendance)).thenReturn(dto);

        Page<AttendanceDetailsDto> result = adminAttendanceService.getAttendanceSummary(pageable);

        assertEquals(1, result.getTotalElements());
        assertEquals(dto, result.getContent().getFirst());
    }

    @Test
    void getAttendanceStatistics_ShouldReturnStatistics_WhenValid() {
        var eventId = 1L;
        var userId = 2L;

        Map<String, Object> mockStats = Map.of("total", 10, "present", 7, "absent", 3);
        when(attendanceRepository.calculateStatistics(eventId, userId)).thenReturn(mockStats);

        Map<String, Object> result = adminAttendanceService.getAttendanceStatistics(eventId, userId);

        assertEquals(mockStats, result);
    }

    @Test
    void getAttendanceStatistics_ShouldThrowException_WhenNoInputProvided() {
        var exception = assertThrows(ApiException.class,
                () -> adminAttendanceService.getAttendanceStatistics(null, null));

        assertEquals("Either eventId or userId must be provided", exception.getMessage());
    }
}
