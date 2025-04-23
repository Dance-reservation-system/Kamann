package pl.kamann.infrastructure.appuser.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.auth.AuthSessionFacade;
import pl.kamann.application.auth.EmailConfirmationFacade;
import pl.kamann.application.auth.PasswordManagementFacade;
import pl.kamann.application.auth.TokenRefreshFacade;
import pl.kamann.application.auth.UserAccountFacade;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.infrastructure.security.ResetPasswordRequest;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Validated
@Slf4j
@Tag(name = "1. login", description = "User access controller")
public class UserAccessController {

    private final AuthSessionFacade authSessionFacade;
    private final TokenRefreshFacade tokenRefreshFacade;
    private final UserAccountFacade userAccountFacade;
    private final PasswordManagementFacade passwordManagementFacade;
    private final EmailConfirmationFacade emailConfirmationFacade;

    @PostMapping("/login")
    @Operation(summary = "User Login", description = "Authenticates the user and returns a JWT token.")
    public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
        return ResponseEntity.ok(authSessionFacade.login(request));
    }

    @PostMapping("/refresh-token")
    @Operation(summary = "Refresh Token", description = "Refreshes the JWT token using refresh token cookie.")
    public ResponseEntity<LoginResponse> refreshToken(@CookieValue("refresh_token") String refreshToken, HttpServletResponse response) {
        return ResponseEntity.ok(tokenRefreshFacade.refreshAccessToken(refreshToken, response));
    }

    @PostMapping("/register-customer")
    @Operation(summary = "Customer Registration", description = "Registers a new customer.")
    public ResponseEntity<AppUserDto> registerCustomer(@RequestBody @Valid RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userAccountFacade.registerCustomer(request));
    }

    @PostMapping("/register-instructor")
    @Operation(summary = "Instructor Registration", description = "Registers a new instructor.")
    public ResponseEntity<AppUserDto> registerInstructor(@RequestBody @Valid RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userAccountFacade.registerInstructor(request));
    }

    @GetMapping("/confirm")
    @Operation(summary = "Confirm a user account", description = "Confirm a user account using the provided token.")
    public ResponseEntity<String> confirmUserAccount(@RequestParam("token") String token) {
        emailConfirmationFacade.confirmAccount(token);
        return ResponseEntity.ok("Your account has been confirmed.");
    }

    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/me")
    @Operation(summary = "Get Logged-in User", description = "Returns the profile of the currently authenticated user.")
    public ResponseEntity<AppUserDto> getLoggedInUser(HttpServletRequest request) {
        return ResponseEntity.ok(authSessionFacade.getLoggedInUser(request));
    }

    @PostMapping("/request-password-reset")
    @Operation(summary = "Request Password Reset", description = "Send a reset password email to user.")
    public ResponseEntity<String> requestPasswordReset(@RequestParam String email) {
        passwordManagementFacade.requestPasswordReset(email);
        return ResponseEntity.ok("If an account exists with that email, a password reset email has been sent.");
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset Password", description = "Reset the password using a token.")
    public ResponseEntity<String> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        passwordManagementFacade.resetPasswordWithToken(request);
        return ResponseEntity.ok("Password has been reset successfully.");
    }

    @PostMapping("/delete-request")
    @Operation(summary = "Request Account Deletion", description = "Request account deletion by email.")
    public ResponseEntity<String> requestAccountDeletion(@RequestParam String email) {
        userAccountFacade.requestAccountDeletion(email);
        return ResponseEntity.ok("Account deletion requested.");
    }
}
