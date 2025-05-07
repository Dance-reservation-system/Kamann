package pl.kamann.domain.event.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.domain.event.EventType;

import java.util.Optional;

public interface EventTypeRepository extends JpaRepository<EventType, Long> {
    Optional<EventType> findByName(String eventName);

}