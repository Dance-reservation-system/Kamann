package pl.kamann.infrastructure.email;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.handler.ExceptionHandlerService;
import pl.kamann.domain.appuser.UserLookupService;
import pl.kamann.domain.authuser.ValidationService;
import pl.kamann.infrastructure.security.jwt.JwtUtils;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.authuser.TokenType;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.infrastructure.authuser.scheduler.ScheduledTaskService;
import pl.kamann.infrastructure.security.jwt.TokenService;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class ConfirmUserService {

    private final TokenService tokenService;
    private final ValidationService validationService;
    private final UserLookupService userLookupService;
    private final ExceptionHandlerService exceptionHandlerService;

    private final EmailSender emailSender;
    private final JwtUtils jwtUtils;
    private final ScheduledTaskService scheduledTaskService;

    private final AuthUserRepository authUserRepository;


    private void sendConfirmationEmail(AuthUser authUser, String token) {
        String confirmationLink = tokenService.generateLink(tokenService.getConfirmationLink(), token);
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

    public void sendConfirmationEmail(AuthUser authUser) {
        String token = tokenService.generateToken(authUser.getEmail(), TokenType.CONFIRMATION);
        sendConfirmationEmail(authUser, token);
        scheduledTaskService.scheduleDeletionUser(authUser.getEmail());
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

            scheduledTaskService.cancelTask(email);

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