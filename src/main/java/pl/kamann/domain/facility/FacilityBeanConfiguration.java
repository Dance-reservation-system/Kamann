package pl.kamann.domain.facility;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class FacilityBeanConfiguration {

 @Bean
 FacilityService facilityService(FacilityRepository facilityRepository) {
  return new FacilityService(facilityRepository);
 }

 @Bean
 FacilityFacade facilityFacade(FacilityService facilityService) {
  return new FacilityFacade(facilityService);
 }

}
