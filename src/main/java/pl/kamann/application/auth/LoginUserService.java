package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.security.TokenProvider;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;

@Service
@RequiredArgsConstructor
public class LoginUserService {

    private final AuthUserRepository authUserRepository;
    private final TokenProvider tokenProvider;
    private final PasswordHasher passwordHasher;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        AuthUser authUser = authUserRepository.findByEmail(new Email(request.email()))
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!authUser.getPassword().matches(request.password(), passwordHasher)) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        String token = tokenProvider.generateToken(authUser);

        return new LoginResponse(token);
    }
}