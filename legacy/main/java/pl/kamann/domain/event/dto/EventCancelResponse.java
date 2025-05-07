package pl.kamann.domain.event.dto;

public record EventCancelResponse(
        Long eventId,
        String message
) {
}
