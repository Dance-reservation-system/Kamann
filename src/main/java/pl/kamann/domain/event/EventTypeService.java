package pl.kamann.domain.event;

import org.springframework.stereotype.Service;

@Service
public class EventTypeService {

    private final EventTypeRepository eventTypeRepository;

    public EventTypeService(EventTypeRepository eventTypeRepository) {
        this.eventTypeRepository = eventTypeRepository;
    }

    public EventType findOrCreateEventType(String eventTypeName) {
        String normalizedName = eventTypeName.trim().toLowerCase();
        return eventTypeRepository.findByName(normalizedName)
                .orElseGet(() -> {
                    EventType newEventType = EventType.builder()
                            .name(normalizedName)
                            .build();
                    return eventTypeRepository.save(newEventType);
                });
    }
}