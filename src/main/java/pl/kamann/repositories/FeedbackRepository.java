package pl.kamann.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.entities.appuser.Feedback;

public interface FeedbackRepository extends JpaRepository<Feedback, Long> {
}
