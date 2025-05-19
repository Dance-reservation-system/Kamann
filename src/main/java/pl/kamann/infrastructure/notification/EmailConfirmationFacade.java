package pl.kamann.infrastructure.notification;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.port.EmailConfirmationPort;
import pl.kamann.domain.entity.AuthUser;

@Service
@RequiredArgsConstructor
public class EmailConfirmationFacade {

    private final EmailConfirmationPort emailConfirmationService;

    @Transactional
    public void confirmAccount(String token) {
        emailConfirmationService.confirmAccount(token);
    }

    @Transactional
    public void sendConfirmationEmail(AuthUser authUser) {
        emailConfirmationService.sendConfirmationEmail(authUser);
    }
}