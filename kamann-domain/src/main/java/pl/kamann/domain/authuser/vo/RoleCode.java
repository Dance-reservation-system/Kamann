package pl.kamann.domain.authuser.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum RoleCode {
    CLIENT("CLIENT"),
    INSTRUCTOR("INSTRUCTOR");

    private final String code;
}
