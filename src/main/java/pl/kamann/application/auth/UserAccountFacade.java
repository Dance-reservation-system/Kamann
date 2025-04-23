package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.service.RegisterUserService;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.dto.RegisterRequest;

@Service
@RequiredArgsConstructor
public class UserAccountFacade {

    private final RegisterUserService registerUserService;
    private final ManageUserAccountService manageUserAccountService;

    @Transactional
    public AppUserDto registerCustomer(RegisterRequest request) {
        return registerUserService.registerCustomer(request);
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return registerUserService.registerInstructor(request);
    }

    @Transactional
    public void requestAccountDeletion(String email) {
        manageUserAccountService.requestAccountDeletion(email);
    }
}
