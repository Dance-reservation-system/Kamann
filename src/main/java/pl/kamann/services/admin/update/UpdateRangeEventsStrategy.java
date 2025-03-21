package pl.kamann.services.admin.update;

import org.springframework.stereotype.Component;
import pl.kamann.repositories.OccurrenceEventRepository;

@Component
public class UpdateRangeEventsStrategy implements UpdateStrategy {
    private OccurrenceEventRepository occurrenceEventRepository;

    @Override
    public void update(UpdateCriteria updateCriteria) {

    }
}
