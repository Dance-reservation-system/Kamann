package pl.kamann.infrastructure.email;

import java.util.Locale;

public record EmailDetails(
        String to,
        String type,
        Locale userLocale,
        String content
) {
}
