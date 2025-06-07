package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.command.RegisterClientCommand;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.factory.UserAccountFactory;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;

@Service
@RequiredArgsConstructor
public class RegisterClientService {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final UserAccountFactory userAccountFactory;
    private final EmailConfirmationFacade emailConfirmationFacade;

    @Transactional
    public void register(RegisterClientCommand request) {
        Email email = new Email(request.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("User with email already exists");
        }

        var user = userAccountFactory.createClient(
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
