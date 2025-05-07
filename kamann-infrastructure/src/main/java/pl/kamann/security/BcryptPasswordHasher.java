package pl.kamann.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.kamann.application.auth.PasswordHasher;

@Component
public class BcryptPasswordHasher implements PasswordHasher {
    private final PasswordEncoder encoder = new BCryptPasswordEncoder();

    public boolean matches(String raw, String encoded) {
        return encoder.matches(raw, encoded);
    }

    public String encode(String raw) {
        return encoder.encode(raw);
    }
}