package pl.kamann.domain.attendance;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.GetLoggedInUserService;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.event.EventLookupService;
import pl.kamann.domain.event.OccurrenceEvent;
import pl.kamann.domain.membershipcard.ClientMembershipCardService;
import pl.kamann.infrastructure.handler.ApiException;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ClientAttendanceService {

    private final AttendanceRepository attendanceRepository;
    private final ClientMembershipCardService clientMembershipCardService;
    private final GetLoggedInUserService getLoggedInUser;
    private final EventLookupService eventLookupService;
    private final UserLookupService userLookupService;

    @Transactional
    public Attendance joinEvent(Long occurrenceEventId, HttpServletRequest request) {
        AppUserDto clientDto = getLoggedInUser.getLoggedInUser(request);
        AppUser client = userLookupService.findUserById(clientDto.id());
        OccurrenceEvent event = eventLookupService.findOccurrenceEventByOccurrenceEventId(occurrenceEventId);

        attendanceRepository.findByUserAndOccurrenceEvent(client, event).ifPresent(att -> {
            throw new ApiException("Client already registered", HttpStatus.CONFLICT, AttendanceCodes.ALREADY_REGISTERED.name());
        });

        if (!event.hasCapacity()) {
            throw new ApiException("Event is full", HttpStatus.BAD_REQUEST, AttendanceCodes.EVENT_FULL.name());
        }

        clientMembershipCardService.deductEntry(client.getId());

        Attendance attendance = Attendance.create(client, event);
        event.registerParticipant(client);
        attendanceRepository.save(attendance);

        return attendance;
    }

    @Transactional
    public Attendance cancelAttendance(Long occurrenceEventId, HttpServletRequest request) {
        AppUserDto clientDto = getLoggedInUser.getLoggedInUser(request);
        AppUser currentUser = userLookupService.findUserById(clientDto.id());
        OccurrenceEvent event = eventLookupService.findOccurrenceEventByOccurrenceEventId(occurrenceEventId);

        Attendance attendance = attendanceRepository.findByUserAndOccurrenceEvent(currentUser, event)
                .orElseThrow(() -> new ApiException(
                        "Attendance not found for user and event",
                        HttpStatus.NOT_FOUND,
                        AttendanceCodes.ATTENDANCE_NOT_FOUND.name()
                ));

        validateCancellation(event);

        AttendanceStatus cancellationStatus = determineCancellationStatus(event);
        attendance.cancelWithStatus(cancellationStatus);
        attendanceRepository.save(attendance);

        publishCancellationEvent(attendance, event, cancellationStatus);

        return attendance;
    }

    public AttendanceStatus determineCancellationStatus(OccurrenceEvent occurrenceEvent) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime cancellationDeadline = occurrenceEvent.getStart().minusHours(24);
        return now.isBefore(cancellationDeadline)
                ? AttendanceStatus.EARLY_CANCEL
                : AttendanceStatus.LATE_CANCEL;
    }

    public void validateCancellation(OccurrenceEvent occurrenceEvent) {
        if (occurrenceEvent.getStart().isBefore(LocalDateTime.now())) {
            throw new ApiException(
                    "Cannot cancel an occurrence that has already started",
                    HttpStatus.BAD_REQUEST,
                    AttendanceCodes.INVALID_ATTENDANCE_STATE.name()
            );
        }
    }

    private void publishCancellationEvent(Attendance attendance, OccurrenceEvent occurrenceEvent,
                                          AttendanceStatus attendanceStatus) {
        // TODO: Implement event publishing
    }

    public Map<String, Object> getAttendanceSummary() {
        throw new UnsupportedOperationException("Not implemented yet.");
    }
}
