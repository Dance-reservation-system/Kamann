package pl.kamann.infrastructure.authuser;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.dto.AppUserResponseDto;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

@Service
@RequiredArgsConstructor
public class AuthAccountService {

    private final JwtUtils jwtUtils;
    private final AppUserMapper appUserMapper;
    private final UserLookupService userLookupService;
    private final AuthUserRepository authUserRepository;
    private final ScheduledTaskService scheduledTaskService;

    public AppUserResponseDto getLoggedInAppUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);
        AppUser appUser = userLookupService.findUserByEmail(email)
                .orElseThrow(() -> new ApiException(
                        "User not found for email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()
                ));

        return appUserMapper.toAppUserResponseDto(appUser);
    }

    public void requestAccountDeletion(String email) {
        AuthUser authUser = authUserRepository.findByEmail(new pl.kamann.domain.authuser.Email(email))
                .orElseThrow(() -> new ApiException(
                        "AuthUser not found for email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()
                ));

        authUser.startDeletion();
        scheduledTaskService.schedulePendingDeletionFinalization(authUser);
        authUserRepository.save(authUser);
    }
}
