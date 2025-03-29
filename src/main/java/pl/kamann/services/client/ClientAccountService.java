package pl.kamann.services.client;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.mappers.UserDetailsMapper;
import pl.kamann.repositories.AccountRepository;

@Service
@RequiredArgsConstructor
public class ClientAccountService {
    private final UserLookupService userLookupService;
    private final UserDetailsMapper userDetailsMapper;
    private final AccountRepository accountRepository;

    @GetMapping
    public UserDetailsDto getUserDetails() {
        AppUser loggedInAppUser = userLookupService.getLoggedInUser();
        AuthUser loggedAuthUser = loggedInAppUser.getAuthUser();

        return userDetailsMapper.toUserDetailsDto(loggedAuthUser, loggedInAppUser);
    }

//    public UserDetailsDto updateUserDetails(UserDetailsDto requestDto) {
//        AppUser loggedInAppUser = userLookupService.getLoggedInUser();
//        AuthUser loggedAuthUser = loggedInAppUser.getAuthUser();
//       UserDetailsDto updatedDto = accountRepository.updateUserAccountDetails(requestDto, loggedInAppUser, loggedAuthUser);
//
//        return updatedDto;
//    }
}
