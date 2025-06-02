package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.auth.command.RegisterInstructorRequest;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.factory.UserAccountFactory;
import pl.kamann.domain.repository.AppUserRepository;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.Email;

@Service
@RequiredArgsConstructor
class RegisterInstructorService {

    private final AuthUserRepository authUserRepository;
    private final AppUserRepository appUserRepository;
    private final UserAccountFactory userAccountFactory;
    private final EmailConfirmationService emailConfirmationService;

    @Transactional
    public AppUser handle (RegisterInstructorRequest request) {
        Email email = new Email(request.email());

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("User with email already exists");
        }

        AuthUser authUser = userAccountFactory.createInstructorAuthUser(email, request.password());
        authUserRepository.save(authUser);

        AppUser appUser = userAccountFactory.createAppUser(
                authUser,
                request.firstName(),
                request.lastName(),
                request.phone()
        );
        appUserRepository.save(appUser);

        emailConfirmationService.sendConfirmationEmail(authUser);

        return appUser;
    }
}