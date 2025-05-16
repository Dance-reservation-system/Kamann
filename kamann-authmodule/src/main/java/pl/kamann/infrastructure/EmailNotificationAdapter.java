package pl.kamann.infrastructure;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import pl.kamann.application.NotificationPort;
import pl.kamann.domain.AuthUser;

@Component
@Slf4j
public class EmailNotificationAdapter implements NotificationPort {

    @Override
    public void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink) {
        log.info("Notify admin {} about instructor request. Confirmation link: {}", adminUser.getEmail().value(), confirmationLink);
    }

    @Override
    public void notifyInstructorOfSubmission(AuthUser instructor) {
        log.info("Notify instructor {} about submission", instructor.getEmail().value());
    }

    @Override
    public void notifyClientOfRegistration(AuthUser client, String confirmationLink) {
        log.info("Notify client {} about registration. Confirmation link: {}", client.getEmail().value(), confirmationLink);
    }

    @Override
    public void notifyUserOfAccountConfirmation(AuthUser user) {
        log.info("Notify user {} of account confirmation", user.getEmail().value());
    }
}