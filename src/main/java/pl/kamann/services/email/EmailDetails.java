package pl.kamann.services.email;

import java.util.Locale;

public record EmailDetails(
        String to,
        String type,
        Locale userLocale,
        String content
) {
}
