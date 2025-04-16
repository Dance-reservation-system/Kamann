package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.config.exception.services.AccountValidationService;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.mappers.UserDetailsMapper;
import pl.kamann.repositories.AppUserRepository;

@Service
@RequiredArgsConstructor
public class AdminUserService {
    private final AppUserRepository appUserRepository;
    private final UserDetailsMapper userDetailsMapper;
    private final AccountValidationService accountValidationService;

    public UserDetailsDto getClientByID(long userId) {
        AppUser user = appUserRepository.getReferenceById(userId);

        accountValidationService.validateClient(user.getAuthUser().getRoles());

        return userDetailsMapper.toUserDetailsDto(user);
    }

    public UserDetailsDto getInstructorByID(long userId) {
        AppUser user = appUserRepository.getReferenceById(userId);

        accountValidationService.validateInstructor(user.getAuthUser().getRoles());

        return userDetailsMapper.toUserDetailsDto(user);
    }
}
