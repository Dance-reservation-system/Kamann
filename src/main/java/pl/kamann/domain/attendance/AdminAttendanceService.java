package pl.kamann.domain.attendance;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.attendance.dto.AttendanceDetailsDto;
import pl.kamann.domain.authuser.StatusCodes;
import pl.kamann.domain.event.EventLookupService;
import pl.kamann.domain.event.OccurrenceEvent;
import pl.kamann.infrastructure.handler.ApiException;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminAttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final AttendanceMapper attendanceMapper;
    private final EventLookupService eventLookupService;

    public void cancelClientAttendance(Long eventId, Long clientId) {
        OccurrenceEvent event = eventLookupService.findOccurrenceEventByOccurrenceEventId(eventId);
        Attendance attendance = attendanceRepository.findByOccurrenceEventAndUserId(event, clientId)
                .orElseThrow(() -> new ApiException(
                        "Attendance not found for event and client",
                        HttpStatus.NOT_FOUND,
                        AttendanceCodes.ATTENDANCE_NOT_FOUND.name()
                ));

        attendanceRepository.delete(attendance);
    }

    public void markAttendance(Long eventId, Long clientId, AttendanceStatus status) {
        OccurrenceEvent event = eventLookupService.findOccurrenceEventByOccurrenceEventId(eventId);
        Attendance attendance = attendanceRepository.findByOccurrenceEventAndUserId(event, clientId)
                .orElseThrow(() -> new ApiException(
                        "Attendance not found for event and client",
                        HttpStatus.NOT_FOUND,
                        AttendanceCodes.ATTENDANCE_NOT_FOUND.name()
                ));

        attendance.overrideStatus(status);
        attendanceRepository.save(attendance);
    }

    public Page<AttendanceDetailsDto> getAttendanceSummary(Pageable pageable) {
        Page<Attendance> attendancePage = attendanceRepository.findAll(pageable);
        return attendancePage.map(attendanceMapper::toAttendanceDetailsDto);
    }

    public Map<String, Object> getAttendanceStatistics(Long eventId, Long userId) {
        if (eventId == null && userId == null) {
            throw new ApiException(
                    "Either eventId or userId must be provided",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }

        return attendanceRepository.calculateStatistics(eventId, userId);
    }
}
