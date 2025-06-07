package pl.kamann.domain.authuser.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum InstructorCode {
    INSTRUCTOR_BUSY("INSTRUCTOR_BUSY"),
    INSTRUCTOR_NOT_FOUND("INSTRUCTOR_NOT_FOUND"),
    REGISTRATION_NOT_FOUND("REGISTRATION_NOT_FOUND");

    private final String code;
}
