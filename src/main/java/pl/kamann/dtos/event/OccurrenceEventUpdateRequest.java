package pl.kamann.dtos.event;

import pl.kamann.services.admin.update.UpdateCriteria;
import pl.kamann.services.admin.update.UpdateStrategy;

import java.time.LocalDateTime;

public record OccurrenceEventUpdateRequest(UpdateStrategy updateStrategy, EventUpdateRequest requestDto, LocalDateTime startAfter, LocalDateTime endBefore) {

}
