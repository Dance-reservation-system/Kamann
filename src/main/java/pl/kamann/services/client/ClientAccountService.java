package pl.kamann.services.client;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import pl.kamann.config.exception.services.AccountValidationService;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.mappers.UserDetailsMapper;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class ClientAccountService {

    private final UserLookupService userLookupService;
    private final UserDetailsMapper userDetailsMapper;
    private final AccountValidationService accountValidationService;

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;

    public UserDetailsDto getUserDetails() {
        AppUser loggedInAppUser = userLookupService.getLoggedInUser();

        return userDetailsMapper.toUserDetailsDto(loggedInAppUser);
    }

    public UserDetailsDto updateUserDetails(UserDetailsDto requestDto) {
        AppUser loggedInAppUser = userLookupService.getLoggedInUser();

        accountValidationService.validateUpdateRequest(requestDto);

        updateUserAccount(loggedInAppUser, requestDto);
        AuthUser authUser = loggedInAppUser.getAuthUser();

        AppUser savedAppUser = appUserRepository.save(loggedInAppUser);
        authUserRepository.save(authUser);


        return userDetailsMapper.toUserDetailsDto(savedAppUser);
    }

    public void updateUserAccount(AppUser user, UserDetailsDto requestDto) {
        if(requestDto.lastName() != null) {
            user.setLastName(requestDto.lastName());
        }

        if (requestDto.firstName() != null) {
            user.setFirstName(requestDto.firstName());
        }

        if (requestDto.phone() != null) {
            user.setPhone(requestDto.phone());
        }

        if(requestDto.email() != null) {
            user.getAuthUser().setEmail(requestDto.email());
        }

        user.setUpdatedAt(LocalDateTime.now());
    }
}
