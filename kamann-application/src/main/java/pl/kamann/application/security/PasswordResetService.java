/**
 * Ubiquitous Language Summary:
 * Application-level infrastructure service that handles password reset flow,
 * including token issuance, email delivery, and password update.
 */
package pl.kamann.application.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.authuser.service.PasswordHasher;
import pl.kamann.domain.authuser.vo.AuthCode;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Password;
import pl.kamann.domain.authuser.vo.TokenType;
import pl.kamann.domain.security.TokenProvider;
import pl.kamann.email.EmailSender;
import pl.kamann.security.ResetPasswordRequest;
import pl.kamann.security.jwt.JwtUtils;
import shared.ApiException;

import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final AuthUserRepository authUserRepository;
    private final TokenProvider tokenProvider;
    private final EmailSender emailSender;
    private final PasswordHasher passwordHasher;
    private final JwtUtils jwtUtils;

    @Transactional
    public void requestPasswordReset(String email) {
        log.info("Password reset requested for email: {}", email);

        AuthUser authUser = validateUserForReset(email);

        sendResetPasswordEmail(authUser);

        log.info("Reset password email sent successfully to: {}", email);
    }

    private AuthUser validateUserForReset(String email) {
        return authUserRepository.findByEmail(new Email(email))
                .orElseThrow(() -> {
                    log.warn("Password reset attempt for non-existent email: {}", email);
                    return new ApiException(
                            "User with email: " + email + " not found.",
                            HttpStatus.NOT_FOUND,
                            AuthCode.USER_NOT_FOUND.name()
                    );
                });
    }

    private void sendResetPasswordEmail(AuthUser authUser) {
        String token = tokenProvider.generateTokenForType(authUser.getEmail(), TokenType.RESET_PASSWORD);
        String resetLink = tokenProvider.generateVerificationLink("/reset-password?token=", token);

        log.info("Sending reset password email to: {}", authUser.getEmail());
        emailSender.sendEmail(authUser.getEmail().value(), resetLink, Locale.ENGLISH, "reset.password");
    }

    @Transactional
    public void resetPasswordWithToken(ResetPasswordRequest request) {
        String token = request.getToken();
        String newPassword = request.getNewPassword();

        log.info("Reset password attempt for token: {}", token);

        if (tokenProvider.isValid(token)) {
            String email = tokenProvider.getSubject(token);

            AuthUser authUser = authUserRepository.findByEmail(new Email(email)).orElseThrow(() ->
                    new ApiException(
                            "User not found",
                            HttpStatus.NOT_FOUND,
                            AuthCode.USER_NOT_FOUND.name()
                    )
            );

            String hashed = passwordHasher.hash(newPassword);
            authUser.resetPassword(new Password(hashed));

            authUserRepository.save(authUser);

            log.info("Password reset successfully for email: {}", authUser.getEmail());
        } else {
            throw new ApiException(
                    "Invalid reset password token.",
                    HttpStatus.NOT_FOUND,
                    AuthCode.INVALID_TOKEN.name()
            );
        }
    }
}
