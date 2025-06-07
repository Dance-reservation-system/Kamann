package pl.kamann.application.port;

import pl.kamann.domain.entity.AuthUser;

public interface EmailConfirmationPort {
    void confirmAccount(String token);
    void sendConfirmationEmail(AuthUser authUser);
}