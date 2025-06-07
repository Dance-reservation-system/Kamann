package pl.kamann.domain.event.dto;

import lombok.Builder;
import pl.kamann.domain.event.vo.EventDifficulty;
import pl.kamann.domain.event.vo.EventStatus;

import javax.validation.constraints.Future;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import javax.validation.constraints.PositiveOrZero;
import java.io.Serializable;
import java.time.LocalDateTime;

@Builder
public record EventDto(
        Long id,

        @NotBlank(message = "Title cannot be blank")
        String title,

        String description,

        @NotNull(message = "Start date/time cannot be null")
        @Future(message = "Start date/time must be in the future")
        LocalDateTime start,

        @NotNull(message = "Duration in minutes cannot be null")
        @Positive(message = "Duration must be positive")
        Integer durationMinutes,

        @NotNull(message = "Creator ID cannot be null")
        Long createdById,

        LocalDateTime createdAt,

        LocalDateTime updatedAt,

        Long instructorId,

        String instructorFullName,

        @PositiveOrZero(message = "Max participants must be zero or a positive number")
        Integer maxParticipants,

        @NotNull(message = "Event status cannot be null")
        EventStatus status,

        @PositiveOrZero(message = "Current participants must be zero or a positive number")
        int currentParticipants,

        @NotNull(message = "Event type ID cannot be null")
        Long eventTypeId,

        @NotNull
        String eventTypeName,

        @NotNull
        EventDifficulty eventDifficulty
) implements Serializable {
}
