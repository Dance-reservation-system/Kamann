package pl.kamann.infrastructure.membershipcard;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;
import pl.kamann.domain.membershipcard.MembershipCardAction;

@Getter
public class MembershipCardEvent extends ApplicationEvent {
    private final Long userId;
    private final MembershipCardAction action;

    public MembershipCardEvent(Object source, Long userId, MembershipCardAction action) {
        super(source);
        this.userId = userId;
        this.action = action;
    }

}