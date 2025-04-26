package pl.kamann.infrastructure.membershipcard.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.domain.membershipcard.ClientMembershipCardService;
import pl.kamann.domain.membershipcard.MembershipCard;

import java.util.List;

@RestController
@RequestMapping("/api/v1/client/membership-cards")
@RequiredArgsConstructor
class ClientMembershipCardController {

    private final ClientMembershipCardService clientMembershipCardService;

    @GetMapping("/available")
    @Operation(summary = "Fetch all available predefined membership cards.")
    public ResponseEntity<List<MembershipCard>> getAvailableMembershipCards() {
        var cards = clientMembershipCardService.getAvailableMembershipCards();
        return ResponseEntity.ok(cards);
    }

    @PostMapping("/request")
    @Operation(summary = "Request a predefined membership card.")
    public ResponseEntity<Void> requestMembershipCard(
            @RequestParam Long cardId,
            HttpServletRequest request
    ) {
        clientMembershipCardService.requestMembershipCard(cardId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/active")
    @Operation(summary = "Get the currently active membership card for the logged-in user.")
    public ResponseEntity<MembershipCard> getActiveMembershipCard(HttpServletRequest request) {
        MembershipCard card = clientMembershipCardService.getActiveCardForLoggedInUser(request);
        return ResponseEntity.ok(card);
    }
}
