package pl.kamann.domain.authuser.service;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.Email;

/**
 * Encapsulates domain rules around AuthUser.
 */
public interface AuthUserPolicy {
    /** Called during registration to guarantee email uniqueness. */
    void ensureEmailNotTaken(Email email);

    /** Called before allowing password changes. */
    void ensureCanChangePassword(AuthUser user);
}