package pl.kamann.services.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.dtos.event.EventUpdateRequest;
import pl.kamann.mappers.EventMapper;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.services.EventValidationService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class AdminOccurrenceEventServiceTest {

    @Mock
    EventValidationService eventValidationService;

    @Mock
    OccurrenceEventRepository occurrenceEventRepository;

    @Mock
    EventMapper eventMapper;

    @Mock
    UserLookupService userLookupService;

    @InjectMocks
    AdminOccurrenceEventService adminOccurrenceEventService;


    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void updateOccurrenceEventByOccurrenceEventId_ShouldThrowException_WhenEventNotFound() {
        //given
        Long id = 1L;
        EventUpdateRequest eventUpdateRequest = Mockito.mock(EventUpdateRequest.class);
        when(occurrenceEventRepository.findById(any())).thenReturn(Optional.empty());
        //when & then
        assertThrows(ApiException.class, () -> adminOccurrenceEventService.updateOccurrenceEventByOccurrenceEventId(id, eventUpdateRequest));
    }
}