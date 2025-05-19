package pl.kamann.domain.service;

import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.vo.Email;

public interface AuthUserPolicy {
    void ensureEmailNotTaken(Email email);
    void ensureCanChangePassword(AuthUser authUser);
}