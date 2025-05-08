package pl.kamann.domain.event.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import pl.kamann.domain.event.vo.EventStatus;

import java.time.LocalDateTime;

@Schema(description = "DTO returned after event creation")
public record CreateEventResponse(

        Long id,
        String title,
        LocalDateTime start,
        Integer durationMinutes,
        EventStatus status
) {
}