package pl.kamann.services.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.mappers.UserDetailsMapper;
import pl.kamann.repositories.AppUserRepository;

@Service
@RequiredArgsConstructor
public class AdminUserService {
    private final AppUserRepository appUserRepository;
    private final UserDetailsMapper userDetailsMapper;

    public UserDetailsDto getUserByID(long userId) {
        AppUser user = appUserRepository.getReferenceById(userId);

        return userDetailsMapper.toUserDetailsDto(user);
    }
}
