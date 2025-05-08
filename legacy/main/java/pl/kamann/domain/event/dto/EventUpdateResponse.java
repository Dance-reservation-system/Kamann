package pl.kamann.domain.event.dto;

import pl.kamann.domain.event.vo.EventStatus;

import java.time.LocalDateTime;

public record EventUpdateResponse(

        Long id,
        String title,
        String description,
        LocalDateTime start,
        Integer durationMinutes,
        EventStatus status,
        LocalDateTime updatedAt,
        Long instructorId,
        Integer maxParticipants
) {
}