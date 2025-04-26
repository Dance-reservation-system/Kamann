package pl.kamann.domain.authuser;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RoleCodes {
    CLIENT("CLIENT"),
    INSTRUCTOR("INSTRUCTOR");

    private final String code;
}
