/**
 * Ubiquitous Language Summary:
 * Application service for confirming user accounts and sending confirmation emails.
 */
package pl.kamann.application.auth;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.notification.NotificationService;
import pl.kamann.application.security.TokenProvider;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.TokenType;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.handler.ExceptionHandlerService;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailConfirmationService {

    private final TokenProvider tokenProvider;
    private final JwtUtils jwtUtils;
    private final UserLookupService userLookupService;
    private final ExceptionHandlerService exceptionHandlerService;
    private final ScheduledTaskService scheduledTaskService;
    private final AuthUserRepository authUserRepository;
    private final NotificationService notificationService;

    public void sendConfirmationEmail(AuthUser authUser) {
        String token = tokenProvider.generateTokenForType(authUser.getEmail(), TokenType.CONFIRMATION);
        String confirmationLink = tokenProvider.generateVerificationLink("/confirm?token=", token);

        if (authUser.getRoles().stream().anyMatch(role -> role.getName().equals(Role.INSTRUCTOR.getName()))) {
            List<AuthUser> adminUsers = authUserRepository.findAdminUser();
            for (AuthUser adminUser : adminUsers) {
                notificationService.notifyAdminsOfInstructorRequest(adminUser, confirmationLink);
            }
            notificationService.notifyInstructorOfSubmission(authUser);
        } else {
            notificationService.notifyClientOfRegistration(authUser, confirmationLink);
        }

        scheduledTaskService.schedulePendingDeletionFinalization(authUser);
    }

    @Transactional
    public void confirmAccount(String token) {
        if (!jwtUtils.validateToken(token, TokenType.CONFIRMATION)) {
            throw new ApiException("Invalid confirmation token.", HttpStatus.BAD_REQUEST, AuthCodes.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);
        AuthUser user = userLookupService.findUserByEmail(email)
                .map(AppUser::getAuthUser)
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND, AuthCodes.USER_NOT_FOUND.name()));

        if (user.isEnabled()) {
            exceptionHandlerService.handleUserAlreadyConfirmedException(email);
        }

        user.activate();
        authUserRepository.save(user);
        scheduledTaskService.cancelPendingDeletionTask(user.getEmail().getValue());

        notificationService.notifyUserOfAccountConfirmation(user);
    }
}
