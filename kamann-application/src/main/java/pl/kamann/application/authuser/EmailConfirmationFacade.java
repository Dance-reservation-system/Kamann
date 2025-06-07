package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.authuser.aggregate.AuthUser;

@Service
@RequiredArgsConstructor
public class EmailConfirmationFacade {

    private final EmailConfirmationService emailConfirmationService;

    @Transactional
    public void confirmAccount(String token) {
        emailConfirmationService.confirmAccount(token);
    }

    @Transactional
    public void sendConfirmationEmail(AuthUser authUser) {
        emailConfirmationService.sendConfirmationEmail(authUser);
    }
}