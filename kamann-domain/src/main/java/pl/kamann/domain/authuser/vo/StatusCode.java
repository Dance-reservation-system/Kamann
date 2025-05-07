package pl.kamann.domain.authuser.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum StatusCode {
    INVALID_INPUT("INVALID_INPUT"),
    NO_RESULTS("NO_RESULTS"),
    INVALID_OPENING_CLOSING_HOURS("INVALID_OPENING_CLOSING_HOURS");

    private final String code;
}
