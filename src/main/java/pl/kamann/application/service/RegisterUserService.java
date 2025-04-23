package pl.kamann.application.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.auth.registration.UserRegistrationService;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.domain.authuser.validation.AuthUserValidator;

@Service
@RequiredArgsConstructor
public class RegisterUserService {

    private final AuthUserValidator authUserValidator;
    private final UserRegistrationService userRegistrationService;

    @Transactional
    public AppUserDto registerCustomer(RegisterRequest request) {
        return registerWithRole(request, Role.CUSTOMER.getName());
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return registerWithRole(request, Role.INSTRUCTOR.getName());
    }

    private AppUserDto registerWithRole(RegisterRequest request, String roleCode) {
        authUserValidator.validateEmailNotTaken(new Email(request.email()));
        return userRegistrationService.registerUser(request, roleCode);
    }
}