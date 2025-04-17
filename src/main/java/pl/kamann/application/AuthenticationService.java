package pl.kamann.application;

import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;

@Service
public class AuthenticationService {

    private final AuthUserRepository authUserRepository;

    public AuthenticationService(AuthUserRepository authUserRepository) {
        this.authUserRepository = authUserRepository;
    }

    public AuthUser validateUser(String email) {
        return authUserRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }
}