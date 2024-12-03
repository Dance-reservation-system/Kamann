package pl.kamann.repositories.admin;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.kamann.entities.reports.AttendanceStatEntity;

@Repository
public interface AttendanceStatRepository extends JpaRepository<AttendanceStatEntity, Long> {
}
