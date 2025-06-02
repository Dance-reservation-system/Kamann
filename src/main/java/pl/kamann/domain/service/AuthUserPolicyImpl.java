package pl.kamann.domain.service;

import org.springframework.stereotype.Component;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.vo.Email;

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