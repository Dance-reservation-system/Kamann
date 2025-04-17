package pl.kamann.config.recurrence;

import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import pl.kamann.dtos.OccurrenceEventDto;
import pl.kamann.dtos.OccurrenceEventLightDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.EventType;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.OccurrenceEventMapper;

import java.time.LocalDateTime;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class OccurrenceEventMapperTest {

    private final OccurrenceEventMapper occurrenceEventMapper = Mappers.getMapper(OccurrenceEventMapper.class);

    @Test
    void toEventLightDto_shouldMapOccurrenceEventCorrectly() {
        AppUser instructor = AppUser.builder().id(2L).firstName("Jane").lastName("Smith").build();
        Event event = Event.builder()
                .id(50L)
                .title("Evening Pilates")
                .durationMinutes(90)
                .build();
        LocalDateTime meetingDate = LocalDateTime.of(2025, 5, 10, 18, 0);
        OccurrenceEvent occ = OccurrenceEvent.builder()
                .id(200L)
                .event(event)
                .meetingDate(meetingDate)
                .instructor(instructor)
                .build();

        OccurrenceEventLightDto lightDto = occurrenceEventMapper.toOccurrenceEventLightDto(occ);

        assertEquals(occ.getEvent().getId(), lightDto.eventId());
        assertEquals(occ.getId(), lightDto.occurrenceId());
        assertEquals(occ.getMeetingDate(), lightDto.start());
        assertEquals(occ.getMeetingDate().plusMinutes(occ.getEvent().getDurationMinutes()), lightDto.end());
        assertEquals(event.getTitle(), lightDto.title());
        assertEquals("Jane Smith", lightDto.instructorName());
    }

    @Test
    void toDto_shouldMapOccurrenceEventDetailedEventDto() {
        AppUser instructor = AppUser.builder().id(2L).firstName("Jane").lastName("Smith").build();
        AppUser creator = AppUser.builder().id(1L).build();
        EventType type = EventType.builder().id(1L).name("Pilates").build();
        LocalDateTime start = LocalDateTime.of(2025, 5, 10, 18, 0);

        Event event = Event.builder()
                .id(50L)
                .title("Evening Pilates")
                .eventType(type)
                .releaseDate(start)
                .maxParticipants(15)
                .durationMinutes(90)
                .instructor(instructor)
                .build();
        OccurrenceEvent occ = OccurrenceEvent.builder()
                .id(200L)
                .event(event)
                .meetingDate(start)
                .instructor(instructor)
                .createdBy(creator)
                .seriesIndex(0)
                .attendances(Collections.emptySet())
                .build();

        OccurrenceEventDto dto = occurrenceEventMapper.toOccurrenceEventDto(occ);

        assertEquals(event.getId(), dto.eventId());
        assertEquals(start.toLocalDate(), dto.meetingDate());
        assertEquals(start.toLocalTime(), dto.startTime());
        assertEquals(start.plusMinutes(90).toLocalTime(), dto.endTime());
        assertEquals(90, dto.durationMinutes());
        assertEquals(instructor.getId(), dto.instructorId());
        assertEquals(creator.getId(), dto.createdById());
        assertEquals(0, dto.seriesIndex());
        assertEquals(15, dto.maxParticipants());
        assertEquals(type.getName(), dto.eventTypeName());
        assertEquals("Jane Smith", dto.instructorFullName());
        assertFalse(dto.isModified());
        assertEquals(0, dto.attendanceCount());
    }

}
