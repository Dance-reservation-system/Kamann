/**
 * Handles HTTP requests for client registration.
 */
package pl.kamann.web.auth;

import lombok.RequiredArgsConstructor;
import main.RegisterClientCommand;
import pl.kamann.application.authuser.RegisterClientService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class ClientRegistrationController {

    private final RegisterClientService registerClientService;

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody RegisterClientRequest request) {
        RegisterClientCommand command = new RegisterClientCommand(
                request.email(),
                request.password(),
                request.firstName(),
                request.lastName(),
                request.phone()
        );

        registerClientService.register(command);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    public record RegisterClientRequest(
            String email,
            String password,
            String firstName,
            String lastName,
            String phone
    ) {}
} 
