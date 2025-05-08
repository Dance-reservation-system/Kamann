package pl.kamann.email;

import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.ResourceBundle;

@Component
class ResourceBundleEmailMessageProvider {
    String getMessage(String key, Locale locale) {
        return getBundle(locale).getString(key + ".message");
    }

    String getSubject(String key, Locale locale) {
        return getBundle(locale).getString(key + ".subject");
    }

    private ResourceBundle getBundle(Locale locale) {
        return ResourceBundle.getBundle("messages", locale);
    }

}
