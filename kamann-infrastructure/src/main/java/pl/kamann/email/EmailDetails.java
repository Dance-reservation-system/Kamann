package pl.kamann.email;

import java.util.Locale;

record EmailDetails(
        String to,
        String type,
        Locale userLocale,
        String content
) {
}
