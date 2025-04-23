package pl.kamann.infrastructure.event.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.domain.event.ClientEventQueryService;
import pl.kamann.domain.event.ClientOccurrenceQueryService;
import pl.kamann.domain.event.dto.EventDto;
import pl.kamann.domain.event.dto.EventLightDto;
import pl.kamann.domain.event.dto.OccurrenceEventDto;
import pl.kamann.domain.event.dto.OccurrenceEventLightDto;
import pl.kamann.domain.event.dto.OccurrenceEventScope;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;

@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
@Tag(name = "2. client event controller", description = "Fetch events and occurrences with filtering and pagination.")
public class ClientEventController {

    private final ClientEventQueryService clientEventQueryService;
    private final ClientOccurrenceQueryService clientOccurrenceQueryService;


    @GetMapping("/occurrences")
    @Operation(summary = "Get paginated occurrences", description = "Retrieves paginated occurrences based on scope.")
    public ResponseEntity<PaginatedResponseDto<OccurrenceEventLightDto>> getOccurrences(
            @RequestParam(defaultValue = "UPCOMING", required = false) OccurrenceEventScope scope,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size,
            HttpServletRequest request
    ) {
        return ResponseEntity.ok(clientOccurrenceQueryService.getOccurrences(scope, page, size, request));
    }

    @GetMapping("/occurrences/{occurrenceId}")
    @Operation(
            summary = "Get OccurrenceEvent details by ID",
            description = "Retrieve details of a specific OccurrenceEvent using its unique ID."
    )
    public ResponseEntity<OccurrenceEventDto> getOccurrenceEventById(@PathVariable Long occurrenceId) {
        return ResponseEntity.ok(clientOccurrenceQueryService.getOccurrenceById(occurrenceId));
    }

    @GetMapping("/events")
    @Operation(summary = "Get paginated events", description = "Retrieves a paginated list of events.")
    public ResponseEntity<PaginatedResponseDto<EventLightDto>> getEvents(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return ResponseEntity.ok(clientEventQueryService.getLightEvents(page, size));
    }

    @GetMapping("/events/{eventId}")
    @Operation(
            summary = "Get Event details by ID",
            description = "Retrieve details of a specific Event using its unique ID."
    )
    public ResponseEntity<EventDto> getEventById(
            @PathVariable Long eventId) {
        return ResponseEntity.ok(clientEventQueryService.getEventById(eventId));
    }

    @GetMapping("event-types/{eventType}/events")
    @Operation(summary = "Get events by event type", description = "Retrieves paginated events based on type")
    public ResponseEntity<PaginatedResponseDto<EventDto>> getEventsByType(
            @PathVariable String eventType,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        return ResponseEntity.ok(clientEventQueryService.getEventsByType(eventType, page, size));
    }
}