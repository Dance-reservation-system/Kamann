package pl.kamann.controllers.client;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.*;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.services.client.ClientAccountService;

@RestController
@RequestMapping("/api/v1/account")
@RequiredArgsConstructor
public class ClientAccountControler {

    private final ClientAccountService clientAccountService;
    private final ClientAccountService clientAccountService;
    ClientAccountService clientAccountService;

    @GetMapping
    public ResponseEntity<UserDetailsDto> getUserDetails() {
        return ResponseEntity.ok(clientAccountService.getUserDetails());
    }

//    @PatchMapping
//    public ResponseEntity<UserDetailsDto> updateUserDetails(
//            @RequestBody() UserDetailsDto userDetailsDto
//    ) {
//        return ResponseEntity.ok(clientAccountService.updateUserDetails(userDetailsDto));
//    }
}
