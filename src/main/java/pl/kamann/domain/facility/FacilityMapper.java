package pl.kamann.domain.facility;

import pl.kamann.domain.facility.dto.FacilityDto;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper(componentModel = "spring")
interface FacilityMapper {
    FacilityDto toFacilityDto(Facility facility);
    Facility toFacility(FacilityDto facilityDto);

  FacilityMapper INSTANCE = Mappers.getMapper(FacilityMapper.class);

}
