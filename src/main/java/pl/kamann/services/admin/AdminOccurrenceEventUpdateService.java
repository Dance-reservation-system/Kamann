package pl.kamann.services.admin;

import org.springframework.stereotype.Service;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.repositories.OccurrenceEventRepository;

@Service
public class AdminOccurrenceEventUpdateService {
    private OccurrenceEventRepository occurrenceEventRepository;

    public void updateSingleOccurrenceEvent(Long id, EventUpdateRequest requestDto) {

    }

    public void updateAllOccurrenceEvents(Long id, EventUpdateRequest requestDto) {

    }

    public void updateFutureOccurrenceEvents(Long id, EventUpdateRequest requestDto) {

    }


}
