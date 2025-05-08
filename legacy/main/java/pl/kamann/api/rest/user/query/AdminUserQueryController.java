// src/main/java/pl/kamann/api/rest/user/query/AdminUserQueryController.java
package pl.kamann.api.rest.user.query;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.user.AppUserQueryService;
import pl.kamann.application.user.dto.AppUserDto;
import pl.kamann.application.user.dto.AppUserProfileDto;
import pl.kamann.application.user.query.UserProfileQueryService;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
public class AdminUserQueryController {

    private final AppUserQueryService queryService;
    private final UserProfileQueryService profileService;

    @GetMapping
    @Operation(summary = "List users", description = "Get a paginated list of users, optionally filtered by role")
    public ResponseEntity<PaginatedResponseDto<AppUserDto>> listUsers(
            @ParameterObject PaginationCriteria criteria,
            @RequestParam(required = false) String role
    ) {
        return ResponseEntity.ok(queryService.getUsers(criteria, role));
    }

    @GetMapping("/logged")
    @Operation(summary = "Get my profile", description = "Returns the currently authenticated user’s profile")
    public ResponseEntity<AppUserProfileDto> getMyProfile(HttpServletRequest request) {
        return ResponseEntity.ok(profileService.getCurrentUserProfile(request));
    }
}
