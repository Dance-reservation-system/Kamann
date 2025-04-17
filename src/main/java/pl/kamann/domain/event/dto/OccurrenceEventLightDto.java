package pl.kamann.domain.event.dto;

import java.io.Serializable;
import java.time.LocalDateTime;

public record OccurrenceEventLightDto(
        Long occurrenceId,
        Long eventId,
        LocalDateTime start,
        LocalDateTime end,
        String title,
        String instructorName,
        String eventTypeName
) implements Serializable {
}