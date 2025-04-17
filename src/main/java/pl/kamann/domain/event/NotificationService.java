package pl.kamann.domain.event;

import org.springframework.stereotype.Service;

@Service
public class NotificationService {
    public void notifyParticipants(Event event) {
        System.out.println("Notifying participants of event: " + event.getTitle());
    }
}