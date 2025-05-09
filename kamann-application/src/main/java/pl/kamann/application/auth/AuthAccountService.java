package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.appuser.AppUserMapper;
import pl.kamann.application.appuser.AppUserResponseDto;
import pl.kamann.application.authuser.lookup.AppUserFinder;

import pl.kamann.authuser.scheduler.ScheduledTaskService;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.AuthCode;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.security.jwt.JwtUtils;
import shared.ApiException;

@Service
@RequiredArgsConstructor
public class AuthAccountService {

    private final JwtUtils jwtUtils;
    private final AppUserMapper appUserMapper;
    private final AppUserFinder appUserFinder;
    private final AuthUserRepository authUserRepository;
    private final ScheduledTaskService scheduledTaskService;

    public AppUserResponseDto getLoggedInAppUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token",
                    HttpStatus.UNAUTHORIZED,
                    AuthCode.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);
        AppUser appUser = appUserFinder.findByEmail(email)
                .orElseThrow(() -> new ApiException(
                        "User not found for email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCode.USER_NOT_FOUND.name()
                ));

        return appUserMapper.toAppUserResponseDto(appUser);
    }

    public void requestAccountDeletion(String email) {
        AuthUser authUser = authUserRepository.findByEmail(new Email(email))
                .orElseThrow(() -> new ApiException(
                        "AuthUser not found for email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCode.USER_NOT_FOUND.name()
                ));

        authUser.startDeletion();
        scheduledTaskService.schedulePendingDeletionFinalization(authUser);
        authUserRepository.save(authUser);
    }
}
