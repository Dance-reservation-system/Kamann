package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.auth.command.LoginRequest;
import pl.kamann.application.auth.command.LoginResponse;
import pl.kamann.domain.entity.AuthUser;
import pl.kamann.domain.exception.ApiException;
import pl.kamann.domain.repository.AuthUserRepository;
import pl.kamann.domain.service.PasswordHasher;
import pl.kamann.domain.vo.Email;
import pl.kamann.infrastructure.security.jwt.TokenProvider;

@Service
@RequiredArgsConstructor
class LoginUserService {

    private final AuthUserRepository authUserRepository;
    private final TokenProvider tokenProvider;
    private final PasswordHasher passwordHasher;

    @Transactional
    public LoginResponse handle(LoginRequest request) {
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
