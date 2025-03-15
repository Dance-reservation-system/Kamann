package pl.kamann.services.email;

import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.ResourceBundle;

@Component
public class ResourceBundleEmailMessageProvider {
    public String getMessage(String key, Locale locale) {
        return getBundle(locale).getString(key + ".message");
    }

    public String getSubject(String key, Locale locale) {
        return getBundle(locale).getString(key + ".subject");
    }

    private ResourceBundle getBundle(Locale locale) {
        return ResourceBundle.getBundle("messages", locale);
    }

}
