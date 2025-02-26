package pl.kamann.config.codes;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthCodes {
    UNAUTHORIZED("UNAUTHORIZED"),
    USER_NOT_FOUND("USER_NOT_FOUND"),
    ROLE_NOT_FOUND("ROLE_NOT_FOUND"),
    INVALID_ROLE("INVALID_ROLE"),
    EMAIL_ALREADY_EXISTS("EMAIL_ALREADY_EXISTS"),
    INVALID_TOKEN("INVALID_TOKEN"),
    RESET_PASSWORD_EMAIL_ERROR("RESET_PASSWORD_EMAIL_ERROR"),
    CONFIRMATION_EMAIL_ERROR("CONFIRMATION_EMAIL_ERROR"),
    RESET_PASSWORD_TOKEN_EXPIRED("RESET_PASSWORD_TOKEN_EXPIRED"),
    CONFIRMATION_TOKEN_EXPIRED("CONFIRMATION_TOKEN_EXPIRED"),
    EMAIL_NOT_CONFIRMED("EMAIL_NOT_CONFIRMED");

    private final String code;
}
