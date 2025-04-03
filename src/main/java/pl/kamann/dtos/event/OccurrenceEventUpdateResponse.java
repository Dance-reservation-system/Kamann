package pl.kamann.dtos.event;

import java.util.List;

public record OccurrenceEventUpdateResponse(Integer affectedOccurrenceEvents, List<EventUpdateResponse> responses) {
}
