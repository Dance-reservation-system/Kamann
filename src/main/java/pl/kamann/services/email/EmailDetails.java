package pl.kamann.services.email;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Locale;

@AllArgsConstructor
@Getter
public class EmailDetails {
    private String to;
    private String type;
    private Locale userLocale;
    private String content;
}
