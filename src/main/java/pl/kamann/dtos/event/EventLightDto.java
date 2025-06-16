package pl.kamann.dtos.event;

import pl.kamann.entities.event.SchedulingStatus;

import java.io.Serializable;
import java.time.LocalDateTime;

public record EventLightDto(
        Long id,
        String title,
        LocalDateTime start,
        Integer durationMinutes,
        SchedulingStatus status,
        String eventTypeName
) implements Serializable {
}