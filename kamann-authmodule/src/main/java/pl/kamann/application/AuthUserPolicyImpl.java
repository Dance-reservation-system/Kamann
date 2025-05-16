package pl.kamann.application;

import org.springframework.stereotype.Component;
import pl.kamann.domain.AuthUser;
import pl.kamann.domain.AuthUserPolicy;
import pl.kamann.domain.Email;
import pl.kamann.infrastructure.AuthUserRepository;

@Component
public class AuthUserPolicyImpl implements AuthUserPolicy {

    private final AuthUserRepository authUserRepository;

    public AuthUserPolicyImpl(AuthUserRepository authUserRepository) {
        this.authUserRepository = authUserRepository;
    }

    @Override
    public void ensureEmailNotTaken(Email email) {
        boolean exists = authUserRepository.findByEmail(email).isPresent();
        if (exists) {
            throw new IllegalArgumentException("Email already taken: " + email.value());
        }
    }

    @Override
    public void ensureCanChangePassword(AuthUser authUser) {
        if (!authUser.isEnabled()) {
            throw new IllegalStateException("Inactive users cannot change passwords.");
        }
    }
}