package pl.kamann.dtos;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalTime;

@Builder
public record OccurrenceEventDto(

        @NotNull(message = "Event ID cannot be null")
        Long eventId,

        String eventTypeName,

        Integer durationMinutes,

        int maxParticipants,

        @NotNull(message = "Date cannot be null")
        LocalDate meetingDate,

        @NotNull(message = "Start time cannot be null")
        LocalTime startTime,

        LocalTime endTime,

        Long instructorId,

        String instructorFullName,

        Long createdById,

        int seriesIndex,

        boolean isModified,

        int attendanceCount
) implements Serializable {
}