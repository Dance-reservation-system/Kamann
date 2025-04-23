package pl.kamann.application.notification;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.NotificationException;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.infrastructure.email.EmailSenderFacade;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class NotificationService {

    private final EmailSenderFacade emailSender;

    public void notifyAdminsOfInstructorRequest(AuthUser adminUser, String confirmationLink) {
        try {
            emailSender.sendEmail(adminUser.getEmail().getValue(), confirmationLink, Locale.ENGLISH, "admin.approval");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to send admin approval email", e);
        }
    }

    public void notifyInstructorOfSubmission(AuthUser instructor) {
        try {
            emailSender.sendEmailWithoutConfirmationLink(instructor.getEmail().getValue(), Locale.ENGLISH, "instructor.registration");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify instructor of registration", e);
        }
    }

    public void notifyClientOfRegistration(AuthUser client, String confirmationLink) {
        try {
            emailSender.sendEmail(client.getEmail().getValue(), confirmationLink, Locale.ENGLISH, "client.registration");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify client of registration", e);
        }
    }

    public void notifyUserOfAccountConfirmation(AuthUser user) {
        try {
            emailSender.sendEmailWithoutConfirmationLink(user.getEmail().getValue(), Locale.ENGLISH, "account.confirmed");
        } catch (MessagingException e) {
            throw new NotificationException("Failed to notify user of account confirmation", e);
        }
    }
}
