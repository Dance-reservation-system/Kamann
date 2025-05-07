package pl.kamann.api.event;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.domain.event.vo.EventStatus;
import pl.kamann.domain.event.dto.CreateEventRequest;
import pl.kamann.domain.event.dto.CreateEventResponse;
import pl.kamann.domain.event.dto.EventCancelResponse;
import pl.kamann.domain.event.dto.EventDto;
import pl.kamann.domain.event.dto.EventUpdateRequest;
import pl.kamann.domain.event.dto.EventUpdateResponse;

@RestController
@RequestMapping("/api/v1/admin/events")
@RequiredArgsConstructor
@Tag(name = "3. admin event controller", description = "Control events and event occurrences from admin perspective.")
public class AdminEventController {

    private final EventQueryService eventQueryService;
    private final EventLifecycleService eventLifecycleService;

    @PostMapping
    @Operation(summary = "Create an event", description = "Creates a new event and assigns an instructor.")
    public ResponseEntity<CreateEventResponse> createEvent(
            @RequestBody @Valid CreateEventRequest createEventRequest,
            HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(eventLifecycleService.createEvent(createEventRequest, request));
    }

    @GetMapping
    @Operation(
            summary = "List events",
            description = "Admins can list all events, or filter by instructor if an instructor ID is provided."
    )
    public ResponseEntity<PaginatedResponseDto<EventDto>> listEvents(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return ResponseEntity.ok(eventQueryService.listEvents(page, size));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get event details", description = "Retrieves detailed information about a specific event.")
    public ResponseEntity<EventDto> getEventDetails(
            @PathVariable Long id) {
        return ResponseEntity.ok(eventQueryService.getEventDtoById(id));
    }

    @PatchMapping("/{id}")
    @Operation(summary = "Update event details", description = "Updates event details partially – only fields provided in the request are updated.")
    public ResponseEntity<EventUpdateResponse> updateEventById(
            @PathVariable Long id,
            @RequestBody EventUpdateRequest requestDto
    ) {
        return ResponseEntity.ok(eventLifecycleService.updateEvent(id, requestDto));
    }

    @PostMapping("/{id}/cancel")
    @Operation(
            summary = "Cancel an event",
            description = "Cancels an event and notifies all participants."
    )
    public ResponseEntity<EventCancelResponse> cancelEvent(
            @PathVariable Long id) {
        eventLifecycleService.cancelEvent(id, EventStatus.CANCELED);
        return ResponseEntity.ok(new EventCancelResponse(id, "Event successfully canceled."));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete an event", description = "Deletes an event by its ID.")
    public ResponseEntity<Void> deleteEvent(
            @PathVariable Long id) {
        eventLifecycleService.deleteEvent(id, false);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}/force")
    @Operation(summary = "Force delete an event", description = "Deletes an event even if participants are registered.")
    public ResponseEntity<Void> forceDeleteEvent(
            @PathVariable Long id) {
        eventLifecycleService.deleteEvent(id, true);
        return ResponseEntity.noContent().build();
    }
}
