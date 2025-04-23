package pl.kamann.domain.event;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import pl.kamann.domain.event.dto.EventDto;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;

@Service
@RequiredArgsConstructor
public class EventQueryService {

    private final EventRepository eventRepository;
    private final EventMapper eventMapper;
    private final EventLookupService eventLookupService;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;

    @Cacheable(value = "events", key = "#page + '-' + #size")
    public PaginatedResponseDto<EventDto> listEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);
        Page<Event> events = eventRepository.findAll(pageable);
        return paginationUtil.toPaginatedResponse(events, eventMapper::toEventDto);
    }

    @Cacheable(value = "events", key = "#eventId")
    public EventDto getEventDtoById(Long eventId) {
        Event event = eventLookupService.findEventById(eventId);
        return eventMapper.toEventDto(event);
    }
}
