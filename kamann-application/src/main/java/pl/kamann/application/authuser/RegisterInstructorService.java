// src/main/java/pl/kamann/application/authuser/RegisterInstructorService.java
package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.command.RegisterInstructorCommand;
import pl.kamann.domain.authuser.factory.UserAccountFactory;
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
    private final UserAccountFactory userAccountFactory;
    private final EmailConfirmationFacade emailConfirmationFacade;


    @Transactional
    public void register(RegisterRequest request) {
        Email email = new Email(request.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("User with email already exists");
        }

        var user = userAccountFactory.createInstructor(
                request.email(),
                request.password(),
                request.firstName(),
                request.lastName(),
                request.phone()
        );

        authUserRepository.save(user.authUser());
        appUserRepository.save(user.appUser());

        emailConfirmationFacade.sendConfirmationEmail(user.authUser());
    }
}
