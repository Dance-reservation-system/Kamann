package pl.kamann.domain.event;

import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.event.dto.CreateEventRequest;
import pl.kamann.domain.event.dto.CreateEventResponse;
import pl.kamann.domain.event.dto.EventDto;
import pl.kamann.domain.event.dto.EventLightDto;
import pl.kamann.domain.event.dto.EventUpdateResponse;
import pl.kamann.domain.event.model.Event;

@Mapper(componentModel = "spring")
public interface EventMapper {

    @Mapping(target = "instructorId", source = "instructor.id")
    @Mapping(target = "createdById", source = "createdBy.id")
    @Mapping(target = "instructorFullName", expression = "java(mapInstructorFullName(event))")
    @Mapping(target = "currentParticipants", expression = "java(calculateCurrentParticipants(event))")
    @Mapping(target = "eventTypeId", source = "eventType.id")
    @Mapping(target = "eventTypeName", source = "eventType.name")
    EventDto toEventDto(Event event);

    default String mapInstructorFullName(Event event) {
        return event.getInstructor() != null ? event.getInstructor().getFirstName() + " " + event.getInstructor().getLastName() : null;
    }

    default int calculateCurrentParticipants(Event event) {
        return event.getOccurrences() != null
                ? event.getOccurrences().stream()
                .mapToInt(occ -> occ.getParticipants() != null ? occ.getParticipants().size() : 0)
                .sum()
                : 0;
    }

    @Mapping(target = "createdBy", expression = "java(loggedInUser)")
    @Mapping(target = "instructor", expression = "java(userLookupService.findUserById(request.instructorId()))")
    @Mapping(target = "status", expression = "java(EventStatus.SCHEDULED)")
    Event toEvent(CreateEventRequest request, @Context UserLookupService userLookupService, @Context AppUser loggedInUser);

    CreateEventResponse toCreateEventResponse(Event event);

    EventLightDto toEventLightDto(Event event);

    @Mapping(target = "instructorId", source = "instructor.id")
    EventUpdateResponse toEventUpdateResponse(Event event);
}
