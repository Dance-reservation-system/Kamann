package pl.kamann.web.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.appuser.AppUserDto;
import pl.kamann.application.authuser.lookup.AppUserFinder;
import pl.kamann.domain.appuser.aggregate.AppUser;
import shared.ApiException;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.service.PasswordHasher;
import pl.kamann.domain.authuser.vo.AuthCode;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.security.TokenProvider;
import shared.LoginRequest;
import shared.LoginResponse;

/**
 * Ubiquitous Language Summary:
 * Application service for executing authentication commands like login, registration, and password reset.
 */
@Service
@RequiredArgsConstructor
public class AuthCommandService {

    private final AuthUserRepository authUserRepository;
    private final TokenProvider tokenProvider;
    private final AppUserFinder appUserFinder;
    private final AuthUserMapper authUserMapper;
    private final PasswordHasher passwordHasher;

    public LoginResponse login(String email, String password) {
        AuthUser authUser = authUserRepository.findByEmail(new Email(email))
                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND, AuthCode.USER_NOT_FOUND.name()));

        if (!authUser.getPassword().matches(password, passwordHasher)) {
            throw new ApiException("Invalid password", HttpStatus.UNAUTHORIZED, AuthCode.INVALID_PASSWORD.name());
        }

        String token = tokenProvider.generateToken(authUser);

        AppUser appUser = appUserFinder.findByAuthUser(authUser)
                .orElseThrow(() -> new ApiException("AppUser not found", HttpStatus.NOT_FOUND, AuthCode.USER_NOT_FOUND.name()));

        String fullName = appUser.getFirstName() + " " + appUser.getLastName();
        String userEmail = authUser.getEmail().value();

        return new LoginResponse(token, userEmail, fullName);
    }

    public LoginResponse login(LoginRequest request) {
        return login(request.email(), request.password());
    }

    public AppUserDto registerCustomer(RegisterRequest request) {
        // TODO: Implement customer registration logic
        throw new UnsupportedOperationException("registerCustomer not yet implemented");
    }

    public AppUserDto registerInstructor(RegisterRequest request) {
        // TODO: Implement instructor registration logic
        throw new UnsupportedOperationException("registerInstructor not yet implemented");
    }

    public void confirmAccount(String token) {
        // TODO: Implement account confirmation logic
        throw new UnsupportedOperationException("confirmAccount not yet implemented");
    }

    public void requestPasswordReset(String email) {
        // TODO: Implement password reset request logic
        throw new UnsupportedOperationException("requestPasswordReset not yet implemented");
    }

    public void resetPassword(pl.kamann.security.ResetPasswordRequest dto) {
        // TODO: Implement password reset logic
        throw new UnsupportedOperationException("resetPassword not yet implemented");
    }

    public void requestAccountDeletion(String email) {
        // TODO: Implement account deletion request logic
        throw new UnsupportedOperationException("requestAccountDeletion not yet implemented");
    }
}
