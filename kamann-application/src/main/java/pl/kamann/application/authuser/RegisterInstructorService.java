// src/main/java/pl/kamann/application/authuser/RegisterInstructorService.java
package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.command.RegisterInstructorCommand;
import pl.kamann.domain.security.TokenProvider;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.service.AuthUserPolicy;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Password;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.email.EmailSenderFacade;
import pl.kamann.notification.NotificationPort;

import java.util.Set;

/**
 * Ubiquitous Language Summary:
 * Application service for registering instructors with confirmation workflow and admin notifications.
 */
@Service
@RequiredArgsConstructor
public class RegisterInstructorService {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final AuthUserPolicy authUserPolicy;
    private final NotificationPort notificationPort;
    private final EmailSenderFacade emailSenderFacade;
    private final TokenProvider tokenProvider;

    @Transactional
    public void register(RegisterInstructorCommand command) {
        Email email = new Email(command.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalStateException("Instructor with this email already exists");
        }

        Password password = new Password(command.password());

        AuthUser authUser = AuthUser.register(
                email,
                password,
                Set.of(Role.INSTRUCTOR),
                authUserPolicy
        );

        AppUser appUser = AppUser.create(
                authUser,
                command.firstName(),
                command.lastName(),
                command.phone(),
                command.policy()
        );

        authUserRepository.save(authUser);
        appUserRepository.save(appUser);

        // Confirmation email and admin notifications handled in EmailConfirmationService
    }
}
