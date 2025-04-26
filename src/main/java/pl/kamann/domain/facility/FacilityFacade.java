package pl.kamann.domain.facility;

import lombok.RequiredArgsConstructor;
import pl.kamann.domain.facility.dto.FacilityDto;


@RequiredArgsConstructor
public class FacilityFacade {

    private final FacilityService facilityService;

    public FacilityDto getFacilityById(long facilityId) {
        return  FacilityMapper.INSTANCE.toFacilityDto(facilityService.getFacility(facilityId));
    }

    public FacilityDto createFacility(FacilityDto facilityDto) {
        return  FacilityMapper.INSTANCE.toFacilityDto(
                facilityService.createFacility(
                        FacilityMapper.INSTANCE.toFacility(facilityDto)));
    }

    public FacilityDto updateFacility(long facilityId, FacilityDto facilityDto) {
        return  FacilityMapper.INSTANCE.toFacilityDto(facilityService.updateFacility(facilityId, facilityDto));
    }

    public void deleteFacility(long facilityId) {
        facilityService.deleteFacility(facilityId);
    }
}
