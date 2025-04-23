package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.infrastructure.security.ResetPasswordRequest;
import pl.kamann.infrastructure.security.PasswordResetService;

@Service
@RequiredArgsConstructor
public class PasswordManagementFacade {

    private final PasswordResetService passwordResetService;

    @Transactional
    public void requestPasswordReset(String email) {
        passwordResetService.requestPasswordReset(email);
    }

    @Transactional
    public void resetPasswordWithToken(ResetPasswordRequest request) {
        passwordResetService.resetPasswordWithToken(request);
    }
}