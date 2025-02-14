package pl.kamann.services.client;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import pl.kamann.config.filter.OccurrenceFilter;
import pl.kamann.config.pagination.PaginatedResponseDto;
import pl.kamann.dtos.EventDto;
import pl.kamann.dtos.OccurrenceEventLightDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.mappers.EventMapper;
import pl.kamann.mappers.OccurrenceEventMapper;
import pl.kamann.repositories.EventRepository;
import pl.kamann.repositories.OccurrenceEventRepository;
import pl.kamann.utility.EntityLookupService;
import pl.kamann.utility.PaginationService;
import pl.kamann.utility.PaginationUtil;

@Service
@RequiredArgsConstructor
public class ClientEventService {
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final OccurrenceEventMapper occurrenceEventMapper;
    private final EntityLookupService lookupService;
    private final PaginationService paginationService;
    private final EventRepository eventRepository;
    private final PaginationUtil paginationUtil;
    private final EventMapper eventMapper;

    public PaginatedResponseDto<OccurrenceEventLightDto> getOccurrences(String filter, Pageable pageable) {
        OccurrenceFilter validFilter = OccurrenceFilter.fromString(filter);
        pageable = paginationService.validatePageable(pageable);

        AppUser loggedInUser = lookupService.getLoggedInUser();

        Page<OccurrenceEvent> pagedOccurrences = occurrenceEventRepository.findFilteredOccurrences(
                validFilter.name(), loggedInUser, pageable);

        return paginationUtil.toPaginatedResponse(pagedOccurrences, occurrenceEventMapper::toLightDto);
    }

    public PaginatedResponseDto<EventDto> getEventsByType(String  eventType, int page, int size){

        String capitalizedEventType = eventType.substring(0, 1).toUpperCase() + eventType.substring(1).toLowerCase();

        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());

        pageable = paginationService.validatePageable(pageable);

        Page<Event> pagedEvent = eventRepository.findAllByEventTypeName(capitalizedEventType, pageable);

        return paginationUtil.toPaginatedResponse(pagedEvent, eventMapper::toDto);
    }
}