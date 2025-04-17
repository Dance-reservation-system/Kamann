package pl.kamann.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.dtos.OccurrenceEventDto;
import pl.kamann.dtos.OccurrenceEventLightDto;
import pl.kamann.entities.event.OccurrenceEvent;

@Mapper(componentModel = "spring")
public interface OccurrenceEventMapper {

    @Mapping(target = "eventId", source = "event.id")
    @Mapping(target = "meetingDate", expression = "java(occurrenceEvent.getMeetingDate().toLocalDate())")
    @Mapping(target = "startTime", expression = "java(occurrenceEvent.getMeetingDate().toLocalTime())")
    @Mapping(target = "endTime", expression = "java(occurrenceEvent.getMeetingDate().plusMinutes(occurrenceEvent." +
            "getEvent().getDurationMinutes()).toLocalTime())")
    @Mapping(target = "durationMinutes", source = "event.durationMinutes")
    @Mapping(target = "maxParticipants", source = "event.maxParticipants")
    @Mapping(target = "instructorId", source = "instructor.id")
    @Mapping(target = "createdById", source = "createdBy.id")
    @Mapping(target = "eventTypeName", source = "event.eventType.name")
    @Mapping(target = "instructorFullName", expression = "java(mapInstructorFullName(occurrenceEvent))")
    @Mapping(target = "attendanceCount", expression = "java(occurrenceEvent.getAttendances().size())")
    OccurrenceEventDto toOccurrenceEventDto(OccurrenceEvent occurrenceEvent);

    @Mapping(target = "occurrenceId", source = "id")
    @Mapping(target = "eventId", source = "event.id")
    @Mapping(target = "start", source = "meetingDate")
    @Mapping(target = "end", expression = "java(occurrenceEvent.getEnd())")
    @Mapping(target = "title", source = "event.title")
    @Mapping(target = "instructorName", expression = "java(mapInstructorFullName(occurrenceEvent))")
    @Mapping(target = "eventTypeName", source = "event.eventType.name")
    OccurrenceEventLightDto toOccurrenceEventLightDto(OccurrenceEvent occurrenceEvent);

    default String mapInstructorFullName(OccurrenceEvent occurrenceEvent) {
        return occurrenceEvent.getInstructor() != null ? occurrenceEvent.getInstructor().getFirstName() + " " + occurrenceEvent.getInstructor().getLastName() : null;
    }
}
