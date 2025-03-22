package pl.kamann.services;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.handler.ExceptionHandlerService;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.config.exception.services.ValidationService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.email.EmailSender;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class ConfirmUserService {

    private final TokenService tokenService;
    private final ValidationService validationService;
    private final UserLookupService userLookupService;
    private final ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(1);
    private final ExceptionHandlerService exceptionHandlerService;

    private final EmailSender emailSender;
    private final JwtUtils jwtUtils;

    private final AuthUserRepository authUserRepository;
    private final Map<String, ScheduledFuture<?>> deletionTasks = new ConcurrentHashMap<>();


    private void sendConfirmationEmail(AuthUser authUser, String token) {
        String confirmationLink = tokenService.generateLink(token, tokenService.getConfirmationLink());
        validationService.validateAuthUser(authUser);

        if (authUser.getRoles().stream().anyMatch(role -> role.getName().equals("INSTRUCTOR"))) {
            List<AuthUser> adminUsers = authUserRepository.findAdminUser();
            for (AuthUser adminUser : adminUsers) {
                validationService.validateAuthUser(adminUser);
                emailSender.sendEmail(adminUser.getEmail(), confirmationLink, Locale.ENGLISH, "admin.approval");
            }

            emailSender.sendEmailWithoutConfirmationLink(authUser.getEmail(), Locale.ENGLISH, "instructor.registration");

            log.info("Confirmation email sent successfully to admin: {}", authUser.getEmail());
        } else {
            emailSender.sendEmail(authUser.getEmail(), confirmationLink, Locale.ENGLISH, "client.registration");
            log.info("Confirmation email sent successfully to user: {}", authUser.getEmail());
        }
    }

    private void handleEmailSending(AuthUser authUser) {
        String token = tokenService.generateToken(authUser.getEmail(), TokenType.CONFIRMATION);
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

        if (jwtUtils.validateToken(token, TokenType.CONFIRMATION)) {
            String email = jwtUtils.extractEmail(token);

            AuthUser user = Optional.ofNullable(userLookupService.findUserByEmail(email)).map(AppUser::getAuthUser).orElseThrow(() ->
                    new ApiException(
                            "User not found",
                            HttpStatus.NOT_FOUND,
                            AuthCodes.USER_NOT_FOUND.name()
                    )
            );

            if (user.isEnabled()) {
                exceptionHandlerService.handleUserAlreadyConfirmedException(email);
            }

            user.setEnabled(true);
            user.setStatus(AuthUserStatus.ACTIVE);
            authUserRepository.save(user);

            cancelDeletionTask(email);

            log.info("User account confirmed for: {}", user.getEmail());

            sendConfirmationSuccessEmail(user);
        } else {
            throw new ApiException(
                    "Invalid confirmation token.",
                    HttpStatus.BAD_REQUEST,
                    AuthCodes.INVALID_TOKEN.name()
            );
        }
    }

    public void sendConfirmationSuccessEmail(AuthUser authUser) {
        emailSender.sendEmailWithoutConfirmationLink(authUser.getEmail(), Locale.ENGLISH, "account.confirmed");
        log.info("Account confirmed email sent successfully to user: {}", authUser.getEmail());
    }
}