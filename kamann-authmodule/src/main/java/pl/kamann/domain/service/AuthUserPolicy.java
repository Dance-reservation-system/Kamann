package pl.kamann.domain.service;

import pl.kamann.domain.vo.Email;
import pl.kamann.domain.entity.AuthUser;

public interface AuthUserPolicy {
    void ensureEmailNotTaken(Email email);
    void ensureCanChangePassword(AuthUser authUser);
}