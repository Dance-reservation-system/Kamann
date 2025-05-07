package pl.kamann.domain.event.dto;

import lombok.Builder;

import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalTime;

/**
 * Ubiquitous Language Summary:
 * DTO representing a single scheduled event occurrence (e.g. class session).
 */
@Builder
public record OccurrenceEventDto(

        @NotNull(message = "Event ID cannot be null")
        Long eventId,

        @NotNull(message = "Date cannot be null")
        LocalDate date,

        @NotNull(message = "Start time cannot be null")
        LocalTime startTime,

        LocalTime endTime,

        int durationMinutes,

        boolean canceled,

        Long instructorId,     // mapped from AppUser.getId().value()

        Long createdById,      // mapped from AppUser.getId().value()

        int seriesIndex,

        int maxParticipants,

        String eventTypeName,

        String instructorFullName,

        boolean isModified,

        int attendanceCount
) implements Serializable {}
