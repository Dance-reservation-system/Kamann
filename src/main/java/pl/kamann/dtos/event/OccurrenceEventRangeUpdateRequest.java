package pl.kamann.dtos.event;


import java.time.LocalDateTime;

public record OccurrenceEventRangeUpdateRequest(
        Long id,
        EventUpdateRequest eventUpdateRequestDto,
        LocalDateTime startAfter,
        LocalDateTime endBefore
) {
}