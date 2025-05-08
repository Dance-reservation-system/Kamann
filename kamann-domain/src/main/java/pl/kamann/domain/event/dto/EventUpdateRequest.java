package pl.kamann.domain.event.dto;

import java.time.LocalDateTime;

public record EventUpdateRequest(
        String title,
        String description,
        LocalDateTime start,
        Integer durationMinutes,
        String rrule,
        Long instructorId,
        Integer maxParticipants
) {
}
