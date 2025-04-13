package pl.kamann.services.instructor;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.mappers.UserDetailsMapper;

@Service
@RequiredArgsConstructor
public class InstructorAccountService {

    private final UserLookupService userLookupService;
    private final UserDetailsMapper userDetailsMapper;

    public UserDetailsDto getInstructorDetails() {
        AppUser loggedInAppUser = userLookupService.getLoggedInUser();
        
        return userDetailsMapper.toUserDetailsDto(loggedInAppUser);
    }
}
