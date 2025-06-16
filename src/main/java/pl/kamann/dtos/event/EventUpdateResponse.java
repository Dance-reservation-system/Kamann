package pl.kamann.dtos.event;

import pl.kamann.entities.event.SchedulingStatus;

import java.time.LocalDateTime;

public record EventUpdateResponse(

        Long id,
        String title,
        String description,
        LocalDateTime start,
        Integer durationMinutes,
        SchedulingStatus status,
        LocalDateTime updatedAt,
        Long instructorId,
        Integer maxParticipants
) {
}