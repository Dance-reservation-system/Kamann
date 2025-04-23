package pl.kamann.infrastructure.authuser;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.registration.UserRegistrationService;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.dto.RegisterRequest;

@Service
@RequiredArgsConstructor
public class AuthRegistrationService {

    private final UserRegistrationService userRegistrationService;

    @Transactional
    public AppUserDto registerClient(RegisterRequest request) {
        return userRegistrationService.registerClient(request);
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return userRegistrationService.registerInstructor(request);
    }
}
