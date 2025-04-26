package pl.kamann.domain.membershipcard;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.auth.GetLoggedInUserService;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.membershipcard.exception.MembershipCardCodes;
import pl.kamann.infrastructure.handler.ApiException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ClientMembershipCardService {

    private final MembershipCardRepository membershipCardRepository;
    private final MembershipCardService membershipCardService;
    private final GetLoggedInUserService getLoggedInUser;
    private final UserLookupService userLookupService;

    @Transactional
    public MembershipCard requestMembershipCard(Long cardId, HttpServletRequest request) {
        AppUser client = extractClientFromRequest(request);
        assertClientHasNoActiveCard(client.getId());

        MembershipCard template = membershipCardRepository.findById(cardId)
                .orElseThrow(() -> new ApiException(
                        "Membership card not found.",
                        HttpStatus.NOT_FOUND,
                        MembershipCardCodes.CARD_NOT_FOUND.name()
                ));

        MembershipCard card = MembershipCard.builder()
                .user(client)
                .membershipCardType(template.getMembershipCardType())
                .entrancesLeft(template.getMembershipCardType().getMaxEntrances())
                .price(template.getPrice())
                .startDate(null)
                .endDate(null)
                .paid(false)
                .active(false)
                .pendingApproval(true)
                .build();

        return membershipCardRepository.save(card);
    }

    public List<MembershipCard> getAvailableMembershipCards() {
        return membershipCardRepository.findByUserIsNullAndActiveFalse();
    }

    public MembershipCard getActiveCard(Long clientId) {
        List<MembershipCard> cards = membershipCardRepository.findByUserIdAndActiveTrue(clientId);

        if (cards.isEmpty()) {
            throw new ApiException(
                    "No active membership card found.",
                    HttpStatus.NOT_FOUND,
                    MembershipCardCodes.CARD_NOT_ACTIVE.name()
            );
        }

        if (cards.size() > 1) {
            throw new ApiException(
                    "Multiple active membership cards found.",
                    HttpStatus.CONFLICT,
                    MembershipCardCodes.MULTIPLE_ACTIVE_CARDS.name()
            );
        }

        return cards.getFirst();
    }

    public MembershipCard getActiveCardForLoggedInUser(HttpServletRequest request) {
        AppUser client = extractClientFromRequest(request);
        return getActiveCard(client.getId());
    }

    private AppUser extractClientFromRequest(HttpServletRequest request) {
        var dto = getLoggedInUser.getLoggedInUser(request);
        return userLookupService.findUserById(dto.id());
    }

    private void assertClientHasNoActiveCard(Long clientId) {
        if (membershipCardRepository.findActiveCardByUserId(clientId).isPresent()) {
            throw new ApiException(
                    "Client already has an active membership card.",
                    HttpStatus.BAD_REQUEST,
                    MembershipCardCodes.CARD_ALREADY_EXISTS.name()
            );
        }
    }

    @Transactional
    public MembershipCard deductEntry(Long clientId) {
        MembershipCard activeCard = getActiveCard(clientId);

        if (activeCard.getEntrancesLeft() <= 0) {
            throw new ApiException(
                    "The membership card has no remaining entrances.",
                    HttpStatus.BAD_REQUEST,
                    MembershipCardCodes.NO_ENTRANCES_LEFT.name()
            );
        }

        activeCard.setEntrancesLeft(activeCard.getEntrancesLeft() - 1);
        membershipCardRepository.save(activeCard);

        membershipCardService.logAction(activeCard, activeCard.getUser(), MembershipCardAction.USED, 1);
        return activeCard;
    }
}
