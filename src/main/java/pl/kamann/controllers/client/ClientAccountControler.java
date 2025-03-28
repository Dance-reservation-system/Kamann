package pl.kamann.controllers.client;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.services.client.ClientAccountService;

@RestController
@RequestMapping("/api/v1/account")
@RequiredArgsConstructor
public class ClientAccountControler {

    ClientAccountService clientAccountService;

    @GetMapping
    public ResponseEntity<UserDetailsDto> getUserDetails() {
        return ResponseEntity.ok(clientAccountService.getUserDetails());
    }
}
