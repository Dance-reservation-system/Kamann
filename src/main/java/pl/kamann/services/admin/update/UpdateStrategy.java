package pl.kamann.services.admin.update;

import pl.kamann.dtos.event.EventUpdateRequest;

public interface UpdateStrategy {
    void update(UpdateCriteria updateCriteria, EventUpdateRequest eventUpdateRequest);
}
