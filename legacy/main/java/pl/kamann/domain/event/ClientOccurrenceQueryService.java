package pl.kamann.domain.event;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.GetLoggedInUserService;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.event.dto.OccurrenceEventDto;
import pl.kamann.domain.event.dto.OccurrenceEventLightDto;
import pl.kamann.domain.event.dto.OccurrenceEventScope;
import pl.kamann.domain.event.exceptions.EventCodes;
import pl.kamann.domain.event.model.OccurrenceEvent;
import pl.kamann.domain.event.repository.OccurrenceEventRepository;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;

@Service
@RequiredArgsConstructor
public class ClientOccurrenceQueryService {

    private final OccurrenceEventRepository occurrenceEventRepository;
    private final OccurrenceEventMapper occurrenceEventMapper;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;
    private final GetLoggedInUserService getLoggedInUserService;

    @Cacheable(value = "occurrencesLight", key = "#scope + '-' + #page + '-' + #size")
    public PaginatedResponseDto<OccurrenceEventLightDto> getOccurrences(OccurrenceEventScope scope, int page, int size, HttpServletRequest request) {
        if (scope == null) {
            scope = OccurrenceEventScope.UPCOMING;
        }

        Pageable pageable = PageRequest.of(page, size, Sort.by("start").ascending());
        pageable = paginationService.validatePageable(pageable);

        AppUser client = getLoggedInUserService.getLoggedInDomainUser(request);
        Page<OccurrenceEvent> occurrences = occurrenceEventRepository.findFilteredOccurrences(scope.name(), client, pageable);

        return paginationUtil.toPaginatedResponse(occurrences, occurrenceEventMapper::toOccurrenceEventLightDto);
    }

    @Cacheable(value = "occurrences", key = "#occurrenceId")
    public OccurrenceEventDto getOccurrenceById(Long occurrenceId) {
        OccurrenceEvent occurrence = occurrenceEventRepository.findById(occurrenceId)
                .orElseThrow(() -> new ApiException(
                        "OccurrenceEvent not found with ID: " + occurrenceId,
                        HttpStatus.BAD_REQUEST,
                        EventCodes.OCCURRENCE_NOT_FOUND.name()));
        return occurrenceEventMapper.toOccurrenceEventDto(occurrence);
    }
}
