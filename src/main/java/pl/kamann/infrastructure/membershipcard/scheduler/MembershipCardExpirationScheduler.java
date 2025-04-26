package pl.kamann.infrastructure.membershipcard.scheduler;

import org.springframework.stereotype.Component;
import pl.kamann.domain.membershipcard.MembershipCardExpirationService;

@Component
public class MembershipCardExpirationScheduler {
    private final MembershipCardExpirationService expirationService;

    public MembershipCardExpirationScheduler(MembershipCardExpirationService expirationService) {
        this.expirationService = expirationService;
    }

    public void runExpirationTask() {
        expirationService.expireMembershipCards();
    }
}