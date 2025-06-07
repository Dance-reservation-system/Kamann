package pl.kamann.notification;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.event.model.Event;
import pl.kamann.email.EmailSenderFacade;
import pl.kamann.exception.NotificationException;

import java.util.Locale;

@Service
@RequiredArgsConstructor
@Slf4j
class NotificationService implements NotificationPort{

    private final EmailSenderFacade emailSender;

    public void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink) {
        try {
            emailSender.sendEmail(adminUser.getEmail().value(), confirmationLink, Locale.ENGLISH, "admin.approval");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to send admin approval email", e);
        }
    }

    public void notifyInstructorOfSubmission(AuthUser instructor) {
        try {
            emailSender.sendEmailWithoutConfirmationLink(instructor.getEmail().value(), Locale.ENGLISH, "instructor.registration");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify instructor of registration", e);
        }
    }

    public void notifyClientOfRegistration(AuthUser client, String confirmationLink) {
        try {
            emailSender.sendEmail(client.getEmail().value(), confirmationLink, Locale.ENGLISH, "client.registration");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify client of registration", e);
        }
    }

    public void notifyUserOfAccountConfirmation(AuthUser user) {
        try {
            emailSender.sendEmailWithoutConfirmationLink(user.getEmail().value(), Locale.ENGLISH, "account.confirmed");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify user of account confirmation", e);
        }
    }

    public void notifyParticipants(Event event) {
        log.warn("Notifying participants of event: {}", event.getTitle());
    }
}
