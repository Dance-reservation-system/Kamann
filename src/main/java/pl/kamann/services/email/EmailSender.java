package pl.kamann.services.email;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import pl.kamann.config.exception.handler.ExceptionHandlerService;

import java.util.Locale;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailSender implements EmailSenderFacade {
    private final JavaMailSender javaMailSender;
    private final EmailContentBuilder emailContentBuilder;
    private final ResourceBundleEmailMessageProvider messageProvider;
    private final ExceptionHandlerService exceptionHandlerService;

    public void sendEmail(String to, String link, Locale userLocale, String type) {
        String content = emailContentBuilder.buildConfirmationEmail(type, userLocale, link);
        sendEmailMessage(new EmailDetails(to, type, userLocale, content));
    }

    public void sendEmailWithoutConfirmationLink(String to, Locale userLocale, String type) {
        String content = emailContentBuilder.buildSampleEmail(type, userLocale);
        sendEmailMessage(new EmailDetails(to, type, userLocale, content));
    }

    @Async
    protected void sendEmailMessage(EmailDetails emailDetails){
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(emailDetails.to());
            helper.setSubject(messageProvider.getSubject(emailDetails.type(), emailDetails.userLocale()));
            helper.setText(emailDetails.content(), true);

            javaMailSender.send(message);
        } catch (MessagingException e) {
            log.error("Error sending the confirmation email to user: {}", emailDetails.to(), e);
            exceptionHandlerService.handleEmailSendingError();
        }
    }
}
