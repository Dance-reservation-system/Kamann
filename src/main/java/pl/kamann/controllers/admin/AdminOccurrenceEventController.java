package pl.kamann.controllers.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.dtos.event.OccurrenceEventRangeUpdateRequest;
import pl.kamann.dtos.event.OccurrenceEventUpdateResponse;
import pl.kamann.services.admin.AdminOccurrenceEventService;

@RestController
@RequestMapping("/api/v1/admin/events/{event-id}/occurrences")
@RequiredArgsConstructor
public class AdminOccurrenceEventController {
    private final AdminOccurrenceEventService adminOccurrenceEventService;

    @PatchMapping("/{occurrence-id}")
    public ResponseEntity<OccurrenceEventUpdateResponse> updateOccurrenceEventByOccurrenceEventId(
            @PathVariable(value = "occurrence-id") Long id,
            @RequestBody EventUpdateRequest requestDto

    ) {
        return ResponseEntity.ok(adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(id, requestDto));
    }

    @PatchMapping("/future")
    public ResponseEntity<OccurrenceEventUpdateResponse> updateFutureOccurrencesByEventId(
            @PathVariable(value = "event-id") Long id,
            @RequestBody EventUpdateRequest requestDto

    ) {
        return ResponseEntity.ok(adminOccurrenceEventService.updateFutureOccurrenceEvents(id, requestDto));
    }

    @PatchMapping("/all")
    public ResponseEntity<OccurrenceEventUpdateResponse> updateAllOccurrencesByEventId(
            @PathVariable(value = "event-id") Long id,
            @RequestBody EventUpdateRequest requestDto

    ) {
        return ResponseEntity.ok(adminOccurrenceEventService.updateAllOccurrenceEvents(id, requestDto));
    }

    @PatchMapping("/range")
    public ResponseEntity<OccurrenceEventUpdateResponse> updateSingleOccurrenceById(
            @PathVariable(value = "event-id") Long id,
            @RequestBody OccurrenceEventRangeUpdateRequest requestDto

    ) {
        return ResponseEntity.ok(adminOccurrenceEventService.updateRangeOccurrenceEvents(id, requestDto));
    }
}
