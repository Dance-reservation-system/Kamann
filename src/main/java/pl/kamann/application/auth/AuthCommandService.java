package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.command.ResetPasswordRequest;


@Service
@RequiredArgsConstructor
class AuthCommandService {



    public void requestPasswordReset(String email) {
        // TODO: Implement password reset request logic
        throw new UnsupportedOperationException("requestPasswordReset not yet implemented");
    }

    public void resetPassword(ResetPasswordRequest dto) {
        // TODO: Implement password reset logic
        throw new UnsupportedOperationException("resetPassword not yet implemented");
    }

    public void requestAccountDeletion(String email) {
        // TODO: Implement account deletion request logic
        throw new UnsupportedOperationException("requestAccountDeletion not yet implemented");
    }
}
