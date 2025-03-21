package pl.kamann.utility.dataseed;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import pl.kamann.entities.event.EventDifficulty;
import pl.kamann.entities.event.EventType;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@Getter
public class EventData {
    private final String title;
    private final String description;
    private final LocalDateTime start;
    private final int duration;
    private final int maxParticipants;
    private final EventType eventType;
    private final String recurrenceRule;
    private final EventDifficulty eventDifficulty;
}
