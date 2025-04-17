package pl.kamann.domain.attendance.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.attendance.AttendanceCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class AttendanceNotFoundException extends ApiException {
    public AttendanceNotFoundException() {
        super("Attendance record not found", HttpStatus.NOT_FOUND, AttendanceCodes.ATTENDANCE_NOT_FOUND.name());
    }
}