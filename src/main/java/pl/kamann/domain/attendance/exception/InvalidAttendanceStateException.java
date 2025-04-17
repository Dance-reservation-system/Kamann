package pl.kamann.domain.attendance.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class InvalidAttendanceStateException extends ApiException {
    public InvalidAttendanceStateException(String message) {
        super(message, HttpStatus.BAD_REQUEST, "INVALID_ATTENDANCE_STATE");
    }
}