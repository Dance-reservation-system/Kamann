package pl.kamann.config.codes;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum StatusCodes {
    INVALID_INPUT("INVALID_INPUT"),
    NO_RESULTS("NO_RESULTS"),
    INVALID_OPENING_CLOSING_HOURS("INVALID_OPENING_CLOSING_HOURS");

    private final String code;
}
