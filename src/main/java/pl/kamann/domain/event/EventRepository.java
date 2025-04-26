package pl.kamann.domain.event;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface EventRepository extends JpaRepository<Event, Long> {

    List<Event> findByRruleIsNotNullAndStartAfter(LocalDateTime startDate);

    Optional<Event> findByTitle(String title);

    Page<Event> findAllByInstructorId(Long instructorId, Pageable pageable);

    Page<Event> findAllByEventTypeName(String  eventType, Pageable pageable);
}
