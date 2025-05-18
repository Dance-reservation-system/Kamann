package pl.kamann.infrastructure.notification;

import jakarta.mail.MessagingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
@Slf4j
public class EmailSenderServiceAdapter implements EmailSenderFacade {

    @Override
    public void sendEmail(String to, String confirmationLink, Locale userLocale, String type) throws MessagingException {

    }

    @Override
    public void sendEmailWithoutConfirmationLink(String to, Locale userLocale, String type) throws MessagingException {

    }
}