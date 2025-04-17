package pl.kamann.domain.event.dto;

import pl.kamann.domain.event.EventStatus;

import java.io.Serializable;
import java.time.LocalDateTime;

public record EventLightDto(
        Long id,
        String title,
        LocalDateTime start,
        Integer durationMinutes,
        EventStatus status,
        String eventTypeName
) implements Serializable {
}