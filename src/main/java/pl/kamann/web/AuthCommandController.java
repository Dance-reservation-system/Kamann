package pl.kamann.web;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.auth.AuthCommandFacade;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginRequest;
import pl.kamann.application.auth.command.LoginResponse;
import pl.kamann.application.auth.command.RegisterCustomerRequest;
import pl.kamann.application.auth.command.RegisterInstructorRequest;
import pl.kamann.application.auth.command.ResetPasswordRequest;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
class AuthCommandController {

    private final AuthCommandFacade authFacade;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest dto) {
        return ResponseEntity.ok(authFacade.login(dto));
    }

    @PostMapping("/register-customer")
    public ResponseEntity<AppUserDto> registerCustomer(@RequestBody @Valid RegisterCustomerRequest dto) {
        return ResponseEntity.status(201).body(authFacade.registerCustomer(dto));
    }

    @PostMapping("/register-instructor")
    public ResponseEntity<AppUserDto> registerInstructor(@RequestBody @Valid RegisterInstructorRequest dto) {
        return ResponseEntity.status(201).body(authFacade.registerInstructor(dto));
    }

    @PostMapping("/request-password-reset")
    public ResponseEntity<Void> requestReset(@RequestParam String email) {
        authFacade.requestPasswordReset(email);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid ResetPasswordRequest dto) {
        authFacade.resetPassword(dto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/delete-request")
    public ResponseEntity<Void> requestDeletion(@RequestParam String email) {
        authFacade.requestAccountDeletion(email);
        return ResponseEntity.ok().build();
    }
}
