package pl.kamann.services.email;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
@RequiredArgsConstructor
public class EmailContentBuilder {
    private final ResourceBundleEmailMessageProvider messageProvider;

    public String buildConfirmationEmail(String key, Locale locale, String confirmationLink) {
        return messageProvider.getMessage(key, locale) + "<a href='" + confirmationLink + "'>" + confirmationLink + "</a>";
    }

    public String buildSampleEmail(String key, Locale locale) {
        return messageProvider.getMessage(key, locale);
    }
}

