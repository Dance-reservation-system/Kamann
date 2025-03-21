package pl.kamann.services.admin.update;

import org.springframework.stereotype.Component;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.repositories.OccurrenceEventRepository;

@Component
public class UpdateAllEventsStrategy implements UpdateStrategy {
    private OccurrenceEventRepository occurrenceEventRepository;

    public UpdateAllEventsStrategy(OccurrenceEventRepository occurrenceEventRepository) {
        this.occurrenceEventRepository = occurrenceEventRepository;
    }

    @Override
    public void update(UpdateCriteria updateCriteria, EventUpdateRequest eventUpdateRequest) {
        occurrenceEventRepository.findAllByEvent(eventUpdateRequest.ev)
    }
}
