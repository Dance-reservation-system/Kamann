package pl.kamann.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kamann.entities.facility.Facility;

public interface FacilityRepository extends JpaRepository<Facility, Long> {

}
