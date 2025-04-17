package pl.kamann.infrastructure.facility.controller;

import pl.kamann.domain.facility.FacilityFacade;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.kamann.domain.facility.dto.FacilityDto;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/facility")
 class FacilityController {
    private final FacilityFacade facilityFacade;

    @GetMapping("/{id}")
    @Operation(summary = "Get Facility", description = "Get Facility")
    public ResponseEntity<FacilityDto> getFacility(@PathVariable Long id) {
        return ResponseEntity.ok(facilityFacade.getFacilityById(id));
    }

    @PostMapping
    @Operation(summary = "Create Facility", description = "Create Facility")
    public ResponseEntity<FacilityDto> createFacility(@RequestBody FacilityDto facilityDto) {
        return ResponseEntity.ok(facilityFacade.createFacility(facilityDto));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update Facility", description = "Update Facility")
    public ResponseEntity<FacilityDto> updateFacility(@PathVariable Long id, @RequestBody FacilityDto facilityDto) {
        return ResponseEntity.ok(facilityFacade.updateFacility(id, facilityDto));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete Facility", description = "Delete Facility")
    public ResponseEntity<Void> deleteFacility(@PathVariable Long id) {
        facilityFacade.deleteFacility(id);
        return ResponseEntity.noContent().build();
    }
}
