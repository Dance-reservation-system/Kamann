package pl.kamann.application.auth;



import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.port.EmailConfirmationPort;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.exception.ApiException;
import pl.kamann.domain.port.NotificationPort;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.AuthCode;
import pl.kamann.domain.vo.Email;
import pl.kamann.domain.vo.Role;
import pl.kamann.domain.vo.TokenType;
import pl.kamann.infrastructure.notification.EmailSenderFacade;
import pl.kamann.infrastructure.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.security.jwt.TokenProvider;

import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
@Slf4j
class EmailConfirmationService implements EmailConfirmationPort {

    private final TokenProvider tokenProvider;
    private final ScheduledTaskService scheduledTaskService;
    private final AuthUserRepository authUserRepository;
    private final NotificationPort notificationPort;
    private final EmailSenderFacade emailSenderFacade;

    @Value("${app.base-url}")
    private String baseUrl;

    @Override
    public void sendConfirmationEmail(AuthUser authUser) {
        String token = tokenProvider.generateTokenForType(authUser.getEmail(), TokenType.CONFIRMATION);
        String prefix = baseUrl + "/api/v1/auth/confirm?token=";
        String confirmationLink = tokenProvider.generateVerificationLink(prefix, token);

        try {
            emailSenderFacade.sendEmail(
                    authUser.getEmail().value(),
                    confirmationLink,
                    Locale.getDefault(),
                    "REGISTRATION"
            );
        } catch (MessagingException e) {
            log.error("Failed to send confirmation email to {}", authUser.getEmail(), e);
        }

        if (authUser.getRoles().stream().anyMatch(role -> role.name().equals(Role.INSTRUCTOR.name()))) {
            List<AuthUser> adminUsers = authUserRepository.findByRole(Role.ADMIN);
            for (AuthUser adminUser : adminUsers) {
                notificationPort.notifyAdminsOfInstructorRequest(adminUser, confirmationLink);
            }
            notificationPort.notifyInstructorOfSubmission(authUser);
        } else {
            notificationPort.notifyClientOfRegistration(authUser, confirmationLink);
        }

        scheduledTaskService.schedulePendingDeletionFinalization(authUser);
    }

    @Override
    @Transactional
    public void confirmAccount(String token) {
        if (!tokenProvider.isValid(token)) {
            throw new ApiException("Invalid confirmation token.", HttpStatus.BAD_REQUEST, AuthCode.INVALID_TOKEN.name());
        }

        String email = tokenProvider.getSubject(token);
        AuthUser user = authUserRepository.findByEmail(new Email(email))
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND, AuthCode.USER_NOT_FOUND.name()));

        if (user.isEnabled()) {
            throw new ApiException("User already confirmed", HttpStatus.CONFLICT, AuthCode.ALREADY_CONFIRMED.name());
        }

        user.activate();
        authUserRepository.save(user);
        scheduledTaskService.cancelPendingDeletionTask(user.getEmail().value());

        notificationPort.notifyUserOfAccountConfirmation(user);
    }
}