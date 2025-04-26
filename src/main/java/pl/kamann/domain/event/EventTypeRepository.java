package pl.kamann.domain.event;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface EventTypeRepository extends JpaRepository<EventType, Long> {
    Optional<EventType> findByName(String eventName);

}