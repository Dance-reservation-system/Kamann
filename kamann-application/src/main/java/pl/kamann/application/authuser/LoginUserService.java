package pl.kamann.application.authuser;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Ubiquitous Language Summary:
 * Application service responsible for authenticating a user and issuing JWT tokens.
 */
@Service
@RequiredArgsConstructor
public class LoginUserService {

//    private final AuthUserRepository authUserRepository;
//    private final TokenProvider tokenProvider;
//    private final PasswordHasher passwordHasher;
//
//    @Transactional
//    public LoginResponse login(LoginRequest request) {
//        AuthUser authUser = authUserRepository.findByEmail(new Email(request.email()))
//                .orElseThrow(() -> new ApiException("User not found", HttpStatus.NOT_FOUND, "AUTH_USER_NOT_FOUND"));
//
//        if (!authUser.getPassword().matches(request.password(), passwordHasher)) {
//            throw new ApiException("Invalid credentials", HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS");
//        }
//
//        String token = tokenProvider.generateToken(authUser);
//        return new LoginResponse(token);
//    }
}
