package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import main.RegisterClientCommand;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.factory.UserAccountFactory;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;

/**
 * Application service for registering a new client.
 */
@Service
@RequiredArgsConstructor
public class RegisterClientService {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final UserAccountFactory userAccountFactory;
    private final EmailConfirmationFacade emailConfirmationFacade;

    @Transactional
    public void register(RegisterClientCommand command) {
        Email email = new Email(command.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("User with email already exists");
        }

        UserAccountFactory.UserAccount user = userAccountFactory.createClient(
                command.email(),
                command.password(),
                command.firstName(),
                command.lastName(),
                command.phone()
        );

        authUserRepository.save(user.authUser());
        appUserRepository.save(user.appUser());

        emailConfirmationFacade.sendConfirmationEmail(user.authUser());
    }
}
