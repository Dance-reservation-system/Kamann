package pl.kamann.services.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class EmailSender implements EmailSenderFacade {
    private final JavaMailSender javaMailSender;
    private final EmailContentBuilder emailContentBuilder;
    private final ResourceBundleEmailMessageProvider messageProvider;

    public void sendEmail(String to, String link, Locale userLocale, String type) throws MessagingException {
        String content = emailContentBuilder.buildConfirmationEmail(type, userLocale, link);
        sendEmailMessage(new EmailDetails(to, type, userLocale, content));
    }

    public void sendEmailWithoutConfirmationLink(String to, Locale userLocale, String type) throws MessagingException {
        String content = emailContentBuilder.buildSampleEmail(type, userLocale);
        sendEmailMessage(new EmailDetails(to, type, userLocale, content));
    }

    private void sendEmailMessage(EmailDetails emailDetails) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        helper.setTo(emailDetails.getTo());
        helper.setSubject(messageProvider.getSubject(emailDetails.getType(), emailDetails.getUserLocale()));
        helper.setText(emailDetails.getContent(), true);

        javaMailSender.send(message);
    }
}
