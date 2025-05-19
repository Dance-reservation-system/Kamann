package pl.kamann.domain.event;

import java.time.Instant;

/**
 * Marker interface for all domain events.
 */
public interface DomainEvent {
    /**
     * When the event occurred.
     */
    Instant occurredOn();
}