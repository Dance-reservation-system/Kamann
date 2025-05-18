package pl.kamann.web;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.auth.AuthCommandFacade;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class EmailConfirmationController {

    private final AuthCommandFacade authCommandFacade;

    @GetMapping("/confirm")
    public ResponseEntity<Void> confirmAccount(@RequestParam String token) {
        authCommandFacade.confirmAccount(token);
        return ResponseEntity.ok().build();
    }
}