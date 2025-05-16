package pl.kamann.application;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.AppUser;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.Email;
import pl.kamann.domain.UserAccountFactory;
import pl.kamann.infrastructure.AppUserRepository;
import pl.kamann.infrastructure.AuthUserRepository;

@Service
@RequiredArgsConstructor
public class RegisterCustomerService {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final UserAccountFactory userAccountFactory;
    private final EmailConfirmationFacade emailConfirmationFacade;

    @Transactional
    public AppUser register(RegisterClientCommand request) {
        Email email = new Email(request.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("User with email already exists");
        }

        AuthUser authUser = userAccountFactory.createCustomerAuthUser(email, request.password());
        authUserRepository.save(authUser);

        AppUser appUser = userAccountFactory.createAppUser(authUser, request.firstName(), request.lastName(), request.phone());
        appUserRepository.save(appUser);

        emailConfirmationFacade.sendConfirmationEmail(authUser);

        return appUser;
    }
}