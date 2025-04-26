package pl.kamann.services.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import pl.kamann.application.auth.GetLoggedInUserService;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.membershipcard.ClientMembershipCardService;
import pl.kamann.domain.membershipcard.MembershipCard;
import pl.kamann.domain.membershipcard.MembershipCardAction;
import pl.kamann.domain.membershipcard.MembershipCardRepository;
import pl.kamann.domain.membershipcard.MembershipCardService;
import pl.kamann.domain.membershipcard.MembershipCardType;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.testsupport.AppUserTestFactory;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientMembershipCardServiceTest {

    @Mock
    private MembershipCardRepository membershipCardRepository;

    @Mock
    private MembershipCardService membershipCardService;

    @Mock
    private UserLookupService userLookupService;

    @Mock
    private GetLoggedInUserService getLoggedInUserService;

    @InjectMocks
    private ClientMembershipCardService clientMembershipCardService;

    private AppUser client;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        client = AppUserTestFactory.withId(1L);
    }
//
//    @Test
//    void requestMembershipCardShouldCreateNewCard() {
//        Long cardId = 1L;
//        MembershipCard template = MembershipCard.builder()
//                .id(cardId)
//                .membershipCardType(MembershipCardType.MONTHLY_8)
//                .price(BigDecimal.valueOf(50.00))
//                .active(false)
//                .build();
//
//        when(getLoggedInUserService.getLoggedInUser(any())).thenReturn(null);
//        when(userLookupService.findUserById(client.getId())).thenReturn(client);
//        when(membershipCardRepository.findActiveCardByUserId(client.getId())).thenReturn(Optional.empty());
//        when(membershipCardRepository.findById(cardId)).thenReturn(Optional.of(template));
//        when(membershipCardRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
//
//        MembershipCard result = clientMembershipCardService.requestMembershipCard(cardId, null);
//
//        assertNotNull(result, "Expected saved membership card to not be null");
//        assertEquals(client, result.getUser(), "Expected card user to be the logged-in client");
//        assertEquals(MembershipCardType.MONTHLY_8, result.getMembershipCardType(), "Expected card type to be MONTHLY_8");
//        assertEquals(8, result.getEntrancesLeft(), "Expected card to have 8 entrances");
//        assertFalse(result.isPaid(), "Expected card to be unpaid");
//        assertFalse(result.isActive(), "Expected card to be inactive");
//        assertTrue(result.isPendingApproval(), "Expected card to be pending approval");
//        verify(membershipCardRepository).save(any());
//    }

//    @Test
//    void requestMembershipCardShouldThrowExceptionWhenActiveCardExists() {
//        Long cardId = 1L;
//        MembershipCard activeCard = MembershipCard.builder().active(true).build();
//
//        when(getLoggedInUserService.getLoggedInUser(any())).thenReturn(null);
//        when(userLookupService.findUserById(client.getId())).thenReturn(client);
//        when(membershipCardRepository.findActiveCardByUserId(client.getId())).thenReturn(Optional.of(activeCard));
//
//        ApiException ex = assertThrows(ApiException.class, () -> clientMembershipCardService.requestMembershipCard(cardId, null),
//                "Expected exception when active card already exists");
//        assertEquals("Client already has an active membership card.", ex.getMessage(), "Exception message mismatch");
//        verify(membershipCardRepository, never()).save(any());
//    }

    @Test
    void getAvailableMembershipCardsShouldReturnTemplates() {
        MembershipCard t1 = new MembershipCard();
        MembershipCard t2 = new MembershipCard();

        when(membershipCardRepository.findByUserIsNullAndActiveFalse()).thenReturn(List.of(t1, t2));

        var result = clientMembershipCardService.getAvailableMembershipCards();

        assertNotNull(result, "Expected card template list to not be null");
        assertEquals(2, result.size(), "Expected to retrieve 2 card templates");
    }

    @Test
    void getActiveCardShouldReturnActiveCard() {
        MembershipCard card = MembershipCard.builder().active(true).build();

        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(List.of(card));

        var result = clientMembershipCardService.getActiveCard(client.getId());

        assertNotNull(result, "Expected active card to not be null");
        assertTrue(result.isActive(), "Expected returned card to be active");
    }

    @Test
    void getActiveCardShouldThrowWhenMultiple() {
        MembershipCard c1 = new MembershipCard();
        MembershipCard c2 = new MembershipCard();

        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(List.of(c1, c2));

        ApiException ex = assertThrows(ApiException.class, () -> clientMembershipCardService.getActiveCard(client.getId()),
                "Expected exception when multiple active cards found");
        assertEquals("Multiple active membership cards found.", ex.getMessage(), "Exception message mismatch");
    }

    @Test
    void getActiveCardShouldThrowWhenEmpty() {
        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(Collections.emptyList());

        ApiException ex = assertThrows(ApiException.class, () -> clientMembershipCardService.getActiveCard(client.getId()),
                "Expected exception when no active cards found");
        assertEquals("No active membership card found.", ex.getMessage(), "Exception message mismatch");
    }

    @Test
    void deductEntryShouldLogAndSave() {
        MembershipCard activeCard = MembershipCard.builder()
                .active(true)
                .entrancesLeft(3)
                .user(client)
                .build();

        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(List.of(activeCard));
        when(membershipCardRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var result = clientMembershipCardService.deductEntry(client.getId());

        assertEquals(2, result.getEntrancesLeft(), "Expected entrances to decrease by 1");
        verify(membershipCardService).logAction(activeCard, client, MembershipCardAction.USED, 1);
    }

    @Test
    void deductEntryShouldThrowWhenNoEntrances() {
        MembershipCard card = MembershipCard.builder().entrancesLeft(0).build();

        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(List.of(card));

        ApiException ex = assertThrows(ApiException.class, () -> clientMembershipCardService.deductEntry(client.getId()),
                "Expected exception when entrancesLeft is zero");
        assertEquals("The membership card has no remaining entrances.", ex.getMessage(), "Exception message mismatch");
    }

    @Test
    void deductEntryShouldThrowWhenNoCardsFound() {
        when(membershipCardRepository.findByUserIdAndActiveTrue(client.getId())).thenReturn(Collections.emptyList());

        ApiException ex = assertThrows(ApiException.class, () -> clientMembershipCardService.deductEntry(client.getId()),
                "Expected exception when no active card exists");
        assertEquals("No active membership card found.", ex.getMessage(), "Exception message mismatch");
    }
}
