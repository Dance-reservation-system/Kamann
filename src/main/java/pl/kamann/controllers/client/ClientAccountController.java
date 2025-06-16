package pl.kamann.controllers.client;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.services.client.ClientAccountService;

@RestController
@RequestMapping("/api/v1/client/account")
@RequiredArgsConstructor
@Tag(name = "4. client account controller", description = "Control client accounts.")
public class ClientAccountController {

    private final ClientAccountService clientAccountService;

    @GetMapping
    public ResponseEntity<UserDetailsDto> getClientDetails() {
        return ResponseEntity.ok(clientAccountService.getClientDetails());
    }

    @PatchMapping
    public ResponseEntity<UserDetailsDto> updateClientDetails(
            @RequestBody UserDetailsDto userDetailsDto
    ) {
        return ResponseEntity.ok(clientAccountService.updateClientDetails(userDetailsDto));
    }
}
