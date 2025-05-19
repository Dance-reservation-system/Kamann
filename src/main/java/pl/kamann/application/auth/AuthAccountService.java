/**
 * Ubiquitous Language Summary:
 * Obsługuje logikę konta użytkownika – pobieranie zalogowanego użytkownika i inicjowanie usuwania konta.
 */
package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.exception.ApiException;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.AuthCode;
import pl.kamann.domain.vo.Email;
import pl.kamann.infrastructure.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.security.jwt.JwtUtils;


@Service
@RequiredArgsConstructor
class AuthAccountService {

    private final JwtUtils jwtUtils;
    private final AppUserMapper appUserMapper;
    private final AppUserFinder appUserFinder;
    private final AuthUserRepository authUserRepository;
    private final ScheduledTaskService scheduledTaskService;

    public AppUserResponseDto getLoggedInAppUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token", HttpStatus.UNAUTHORIZED, AuthCode.INVALID_TOKEN.name());
        }

        String email = jwtUtils.getSubject(token);
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
