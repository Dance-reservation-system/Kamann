package pl.kamann.controllers.client;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.entities.appuser.Feedback;
import pl.kamann.services.ClientFeedbackService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/client/feedback")
public class ClientFeedbackController {
    private final ClientFeedbackService clientFeedbackService;

    @PostMapping("/add")
    public ResponseEntity<Void> addFeedback(@RequestBody Feedback feedback) {
        clientFeedbackService.addFeedback(feedback);
        return ResponseEntity.ok().build();
    }
}
