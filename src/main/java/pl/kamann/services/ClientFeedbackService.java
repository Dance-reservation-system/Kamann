package pl.kamann.services;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.entities.appuser.Feedback;
import pl.kamann.repositories.FeedbackRepository;

@Service
@RequiredArgsConstructor
public class ClientFeedbackService {
    public final FeedbackRepository feedbackRepository;

    public void addFeedback(Feedback feedback) {
        feedbackRepository.save(feedback);
    }
}
