package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.service.PasswordHasher;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.security.TokenProvider;
import shared.ApiException;
import shared.LoginRequest;
import shared.LoginResponse;

/**
 * Ubiquitous Language Summary:
 * Application service responsible for authenticating a user and issuing JWT tokens.
 */
@Service
@RequiredArgsConstructor
public class LoginUserService {

    private final AuthUserRepository authUserRepository;
    private final TokenProvider tokenProvider;
    private final PasswordHasher passwordHasher;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        AuthUser authUser = authUserRepository.findByEmail(new Email(request.email()))
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND, "AUTH_USER_NOT_FOUND"));

        if (!authUser.getPassword().matches(request.password(), passwordHasher)) {
            throw new ApiException("Invalid credentials", HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
        }

        String email = authUser.getEmail().value();
        String fullName = "";

        String token = tokenProvider.generateToken(authUser);

        return new LoginResponse(token, email, fullName);
    }
}
