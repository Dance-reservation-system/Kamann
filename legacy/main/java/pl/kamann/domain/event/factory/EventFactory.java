package pl.kamann.domain.event.factory;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.event.vo.EventStatus;
import pl.kamann.domain.event.dto.CreateEventRequest;
import pl.kamann.domain.event.model.Event;

@Component
@RequiredArgsConstructor
class EventFactory {

    private final UserLookupService userLookupService;

    public Event create(CreateEventRequest request, AppUser createdBy) {
        Event event = new Event();

        event.setTitle(request.title());
        event.setDescription(request.description());
        event.setStart(request.start());
        event.setDurationMinutes(request.durationMinutes());
        event.setRrule(request.rrule());
        event.setEventTypeName(request.eventTypeName());
        event.setMaxParticipants(request.maxParticipants());
        event.setEventDifficulty(request.eventDifficulty());

        event.setCreatedBy(createdBy);
        event.setStatus(EventStatus.SCHEDULED);

        if (request.instructorId() != null) {
            event.setInstructor(userLookupService.findUserById(request.instructorId()));
        }

        return event;
    }
}
