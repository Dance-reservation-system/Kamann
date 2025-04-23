package pl.kamann.domain.event;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import pl.kamann.domain.event.dto.EventDto;
import pl.kamann.domain.event.dto.EventLightDto;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;

@Service
@RequiredArgsConstructor
public class ClientEventQueryService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;
    private final EventLookupService eventLookupService;

    @Cacheable(value = "eventsLight", key = "#page + '-' + #size")
    public PaginatedResponseDto<EventLightDto> getLightEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);
        Page<Event> pagedEvents = eventRepository.findAll(pageable);
        return paginationUtil.toPaginatedResponse(pagedEvents, eventMapper::toEventLightDto);
    }

    @Cacheable(value = "events", key = "#eventType + '-' +  #page + '-' + #size")
    public PaginatedResponseDto<EventDto> getEventsByType(String eventType, int page, int size) {
        String capitalizedType = eventType.substring(0, 1).toUpperCase() + eventType.substring(1).toLowerCase();
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);
        Page<Event> pagedEvent = eventRepository.findAllByEventTypeName(capitalizedType, pageable);
        return paginationUtil.toPaginatedResponse(pagedEvent, eventMapper::toEventDto);
    }

    @Cacheable(value = "events", key = "#eventId")
    public EventDto getEventById(Long eventId) {
        Event event = eventLookupService.findEventById(eventId);
        return eventMapper.toEventDto(event);
    }
}
