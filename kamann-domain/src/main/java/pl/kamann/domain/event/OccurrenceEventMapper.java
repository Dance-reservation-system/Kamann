package pl.kamann.domain.event;

import pl.kamann.domain.event.dto.OccurrenceEventDto;
import pl.kamann.domain.event.dto.OccurrenceEventLightDto;
import pl.kamann.domain.event.model.OccurrenceEvent;

public interface OccurrenceEventMapper {

    OccurrenceEventDto toOccurrenceEventDto(OccurrenceEvent occurrenceEvent);

    OccurrenceEventLightDto toOccurrenceEventLightDto(OccurrenceEvent occurrenceEvent);

    default String mapInstructorFullName(OccurrenceEvent occurrenceEvent) {
        return occurrenceEvent.getInstructor() != null ? occurrenceEvent.getInstructor().getFirstName() + " " + occurrenceEvent.getInstructor().getLastName() : null;
    }
}