package pl.kamann.infrastructure.attendance.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.domain.attendance.Attendance;
import pl.kamann.domain.attendance.ClientAttendanceService;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/client/attendance")
@RequiredArgsConstructor
public class ClientAttendanceController {

    private final ClientAttendanceService clientAttendanceService;

    @PostMapping("/{eventId}/join")
    @Operation(summary = "Join an event", description = "Registers the logged-in client to the specified event.")
    public ResponseEntity<Attendance> joinEvent(@PathVariable Long eventId, HttpServletRequest request) {
        var attendance = clientAttendanceService.joinEvent(eventId, request);
        return ResponseEntity.ok(attendance);
    }

    @PostMapping("/{eventId}/cancel")
    @Operation(summary = "Cancel attendance", description = "Cancels the client's attendance for the specified event.")
    public ResponseEntity<String> cancelAttendance(@PathVariable Long eventId, HttpServletRequest request) {
        var attendance = clientAttendanceService.cancelAttendance(eventId, request);
        return ResponseEntity.ok("Attendance for event: " + attendance.getOccurrenceEvent().getEvent().getTitle() + " successfully cancelled.");
    }

    @GetMapping("/summary")
    @Operation(summary = "Get attendance summary", description = "Retrieves the attendance summary for the logged-in client.")
    public ResponseEntity<Map<String, Object>> getAttendanceSummary() {
        Map<String, Object> summary = clientAttendanceService.getAttendanceSummary();
        return ResponseEntity.ok(summary);
    }
}
