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
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        helper.setTo(to);
        helper.setSubject(messageProvider.getSubject(type, userLocale));
        helper.setText(emailContentBuilder.buildConfirmationEmail(type, userLocale, link), true);

        javaMailSender.send(message);
    }

    public void sendEmailWithoutConfirmationLink(String to, Locale userLocale, String type) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);

        helper.setTo(to);
        helper.setSubject(messageProvider.getSubject(type, userLocale));
        helper.setText(emailContentBuilder.buildSampleEmail(type, userLocale), true);

        javaMailSender.send(message);
    }
}
