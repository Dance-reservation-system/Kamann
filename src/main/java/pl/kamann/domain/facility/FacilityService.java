package pl.kamann.domain.facility;

import pl.kamann.domain.facility.dto.FacilityDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import pl.kamann.domain.event.exception.EventCodes;
import pl.kamann.infrastructure.handler.ApiException;

@Slf4j
@RequiredArgsConstructor
class FacilityService {
    private final FacilityRepository facilityRepository;

    @Cacheable(value = "facilities", key = "#id")
    public Facility getFacility(Long id) {
        log.info("Fetching facility with id: {}", id);
        return facilityRepository.findById(id)
                .orElseThrow(() -> notFoundException(id));
    }

    @CachePut(value = "facilities", key = "#result.id")
    public Facility createFacility(Facility facility) {
        return facilityRepository.save(facility);
    }

    @CachePut(value = "facilities", key = "#id")
    @Transactional
    public Facility updateFacility(Long id, FacilityDto updatedData) {
        return facilityRepository.findById(id)
                .map(existing -> {
                    existing.setName(updatedData.name());
                    existing.setAddress(updatedData.address());
                    existing.setOpeningHours(updatedData.openingHours());
                    existing.setClosingHours(updatedData.closingHours());
                    return existing;
                })
                .orElseThrow(() -> notFoundException(id));
    }

    @CacheEvict(value = "facilities", key = "#id")
    public void deleteFacility(Long id) {
        if (!facilityRepository.existsById(id)) {
            throw notFoundException(id);
        }
        facilityRepository.deleteById(id);
        log.info("Deleted facility with id: {}", id);
    }

    private ApiException notFoundException(Long id) {
        return new ApiException(
                "Facility not found with id: " + id,
                HttpStatus.NOT_FOUND,
                EventCodes.EVENT_NOT_FOUND.name()
        );
    }
}
