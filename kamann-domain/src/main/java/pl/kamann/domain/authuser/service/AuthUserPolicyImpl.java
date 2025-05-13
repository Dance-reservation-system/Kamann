package pl.kamann.domain.authuser.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.AuthUserStatus;
import pl.kamann.domain.authuser.vo.Email;

/**
 * Default implementation of AuthUserPolicy.
 */
@Component
@RequiredArgsConstructor
public class AuthUserPolicyImpl implements AuthUserPolicy {

    private final AuthUserRepository authUserRepository;

    @Override
    public void ensureEmailNotTaken(Email email) {
        // throw if there is already a user with this email
        if (authUserRepository.findByEmail(email).isPresent()) {
        // todo implement custom exception

        }
    }

    @Override
    public void ensureCanChangePassword(AuthUser user) {
        // example rule: only ACTIVE users may change password
        if (user.getStatus() != AuthUserStatus.ACTIVE) {
            throw new IllegalStateException(
                "Cannot change password when user status is " + user.getStatus()
            );
        }
    }
}