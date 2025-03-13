package pl.kamann.services;

import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import pl.kamann.config.exception.handler.ExceptionHandlerService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.email.EmailSender;
import pl.kamann.config.exception.services.UserLookupService;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class ConfirmUserService {

    private final EmailSender emailSender;
    private final TokenService tokenService;
    private final JwtUtils jwtUtils;
    private final ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final ExceptionHandlerService exceptionHandlerService;

    private final Map<String, ScheduledFuture<?>> deletionTasks = new ConcurrentHashMap<>();
    private final UserLookupService userLookupService;

    private void sendConfirmationEmail(AuthUser authUser, String token) {
        String confirmationLink = tokenService.generateConfirmationLink(token, tokenService.getConfirmationLink());

        try {
            emailSender.sendEmail(authUser.getEmail(), confirmationLink, Locale.ENGLISH, "registration");
            log.info("Confirmation email sent successfully to user: {}", authUser.getEmail());
        } catch (MessagingException e) {
            log.error("Error sending the confirmation email to user: {}", authUser.getEmail(), e);
            exceptionHandlerService.handleEmailSendingError();
        }
    }

    private void handleEmailSending(AuthUser authUser) {
        String token = tokenService.generateToken(authUser.getEmail(), TokenType.CONFIRMATION, 15 * 60 * 1000);
        sendConfirmationEmail(authUser, token);
        scheduleUserDeletion(authUser.getEmail());
    }

    public void sendConfirmationEmail(AuthUser authUser) {
        handleEmailSending(authUser);
    }

    private void scheduleUserDeletion(String email) {
        cancelDeletionTask(email);

        ScheduledFuture<?> task = scheduledExecutorService.schedule(() -> {
            Optional<AuthUser> authUserOptional = authUserRepository.findByEmail(email);
            if (authUserOptional.isPresent() && !authUserOptional.get().isEnabled()) {
                authUserRepository.delete(authUserOptional.get());
                log.info("User {} deleted due to inactivity after {} minutes", email, 15);
            }
            deletionTasks.remove(email);
        }, 15, TimeUnit.MINUTES);

        deletionTasks.put(email, task);
    }

    private void cancelDeletionTask(String email) {
        ScheduledFuture<?> task = deletionTasks.get(email);
        if (task != null && !task.isDone() && !task.isCancelled()) {
            task.cancel(false);
            log.info("Cancelled scheduled deletion task for user: {}", email);
        }
        deletionTasks.remove(email);
    }

    @Transactional
    public void confirmUserAccount(String token) {
        log.info("Confirming user account for token: {}", token);

        if (!jwtUtils.validateToken(token)) {
            exceptionHandlerService.handleInvalidTokenException();
        }
        if (!jwtUtils.isTokenTypeValid(token, TokenType.CONFIRMATION)) {
            exceptionHandlerService.handleInvalidTokenTypeException();
        }

        String email = jwtUtils.extractEmail(token);
        AppUser userByEmail = userLookupService.findUserByEmail(email);

        if (userByEmail == null) {
            exceptionHandlerService.handleUserNotFoundException(email);
            return;
        }
        AuthUser user = userByEmail.getAuthUser();

        if (user.isEnabled()) {
            exceptionHandlerService.handleUserAlreadyConfirmedException(email);
        }

        user.setEnabled(true);
        user.setStatus(AuthUserStatus.ACTIVE);
        authUserRepository.save(user);

        if (!appUserRepository.existsByAuthUser(user)) {
            AppUser newAppUser = new AppUser();
            newAppUser.setAuthUser(user);
            appUserRepository.save(newAppUser);
        }

        cancelDeletionTask(email);

        log.info("User account confirmed for: {}", user.getEmail());
    }
}
