package pl.kamann.application.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginRequest;
import pl.kamann.application.auth.command.LoginResponse;
import pl.kamann.application.auth.command.RegisterCustomerRequest;
import pl.kamann.application.auth.command.RegisterInstructorRequest;
import pl.kamann.application.auth.command.ResetPasswordRequest;
import pl.kamann.domain.entity.AppUser;
import pl.kamann.domain.entity.AuthUser;

@Component
@RequiredArgsConstructor
public class AuthCommandFacade {

    private final RegisterCustomerService registerCustomerService;
    private final RegisterInstructorService registerInstructorService;
    private final EmailConfirmationService emailConfirmationService;
    private final LoginUserService loginUserService;
    private final AuthCommandService authCommandService;
    private final AppUserMapper appUserMapper;

    public LoginResponse login(LoginRequest command) {
        return loginUserService.handle(command);
    }

    public AppUserDto registerCustomer(RegisterCustomerRequest command) {
        AppUser user = registerCustomerService.handle(command);
        return appUserMapper.toAppUserDto(user);
    }

    public AppUserDto registerInstructor(RegisterInstructorRequest command) {
        AppUser user = registerInstructorService.handle(command);
        return appUserMapper.toAppUserDto(user);
    }

    public void resetPassword(ResetPasswordRequest command) {
        authCommandService.resetPassword(command);
    }

    public void requestPasswordReset(String email) {
        authCommandService.requestPasswordReset(email);
    }

    public void requestAccountDeletion(String email) {
        authCommandService.requestAccountDeletion(email);
    }

    public void confirmAccount(String token) {
        emailConfirmationService.confirmAccount(token);
    }

    public void sendConfirmationEmail(AuthUser authUser) {
        emailConfirmationService.sendConfirmationEmail(authUser);
    }
}