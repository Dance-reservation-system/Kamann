package pl.kamann.domain.membershipcard.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.infrastructure.handler.ApiException;

public class CardNotFoundException extends ApiException {
    public CardNotFoundException() {
        super("Membership card not found.", HttpStatus.NOT_FOUND, MembershipCardCodes.CARD_NOT_FOUND.name());
    }
}