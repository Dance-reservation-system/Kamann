package pl.kamann.web.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.appuser.AppUserDto;
import pl.kamann.security.ResetPasswordRequest;
import shared.LoginRequest;
import shared.LoginResponse;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
class AuthCommandController {

    private final AuthCommandService authCommands;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody @Valid LoginRequest dto
    ) {
        return ResponseEntity.ok(authCommands.login(dto));
    }

    @PostMapping("/register-customer")
    public ResponseEntity<AppUserDto> registerCustomer(
            @RequestBody @Valid RegisterRequest dto
    ) {
        return ResponseEntity.status(201)
                .body(authCommands.registerCustomer(dto));
    }

    @PostMapping("/register-instructor")
    public ResponseEntity<AppUserDto> registerInstructor(
            @RequestBody @Valid RegisterRequest dto
    ) {
        return ResponseEntity.status(201)
                .body(authCommands.registerInstructor(dto));
    }

    @GetMapping("/confirm")
    public ResponseEntity<Void> confirm(@RequestParam String token) {
        authCommands.confirmAccount(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/request-password-reset")
    public ResponseEntity<Void> requestReset(@RequestParam String email) {
        authCommands.requestPasswordReset(email);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(
            @RequestBody @Valid ResetPasswordRequest dto
    ) {
        authCommands.resetPassword(dto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/delete-request")
    public ResponseEntity<Void> requestDeletion(@RequestParam String email) {
        authCommands.requestAccountDeletion(email);
        return ResponseEntity.ok().build();
    }
}
