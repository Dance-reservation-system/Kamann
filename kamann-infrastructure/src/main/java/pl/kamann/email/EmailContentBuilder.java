package pl.kamann.email;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Locale;

@Component
@RequiredArgsConstructor
class EmailContentBuilder {
    private final ResourceBundleEmailMessageProvider messageProvider;

    String buildConfirmationEmail(String key, Locale locale, String confirmationLink) {
        return buildSampleEmail(key, locale) + "<a href='" + confirmationLink + "'>" + confirmationLink + "</a>";
    }

    String buildSampleEmail(String key, Locale locale) {
        return messageProvider.getMessage(key, locale);
    }
}

