package pl.kamann.config.exception.handler;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;

@Service
@RequiredArgsConstructor
public class ExceptionHandlerService {

    public void handleUserAlreadyConfirmedException(String email) {
        throw new ApiException(
                "User with email " + email + " is already confirmed",
                HttpStatus.BAD_REQUEST,
                AuthCodes.USER_ALREADY_CONFIRMED.name()
        );
    }

    public void handleEmailSendingError() {
        throw new ApiException(
                "Error sending the confirmation email.",
                HttpStatus.INTERNAL_SERVER_ERROR,
                AuthCodes.CONFIRMATION_EMAIL_ERROR.name()
        );
    }
}
