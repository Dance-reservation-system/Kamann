/**
 * Ubiquitous Language Summary:
 * REST API controller for admin operations on users,
 * including listing, status updates, and viewing logged-in profile.
 */
package pl.kamann.infrastructure.appuser.controller;

import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.user.AppUserCommandService;
import pl.kamann.application.user.AppUserQueryService;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.dto.AppUserResponseDto;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.infrastructure.authuser.AuthAccountService;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
@Slf4j
public class AdminUserController {

    private final AppUserQueryService appUserQueryService;
    private final AppUserCommandService appUserCommandService;
    private final AuthAccountService authAccountService;

    @GetMapping
    @Operation(
            summary = "Get all users with pagination",
            description = "Retrieve a paginated list of all users in the system filtered by role."
    )
    public ResponseEntity<PaginatedResponseDto<AppUserDto>> getAllUsersByRole(
            @ParameterObject PaginationCriteria criteria,
            @RequestParam(required = false) String role
    ) {
        return ResponseEntity.ok(appUserQueryService.getUsers(criteria, role));
    }

    @GetMapping("/logged")
    @Operation(
            summary = "Get details of logged in user.",
            description = "Retrieve an AppUserDto of currently logged in AppUser."
    )
    public ResponseEntity<AppUserResponseDto> getLoggedInUser(HttpServletRequest request) {
        return ResponseEntity.ok(authAccountService.getLoggedInAppUser(request));
    }

    @PutMapping("/activate/{userId}")
    @Operation(
            summary = "Activate a user account",
            description = "Activate a user account by setting its status to ACTIVE. This endpoint requires the user's ID."
    )
    public ResponseEntity<Void> activateUser(@PathVariable Long userId) {
        appUserCommandService.activateUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/deactivate/{userId}")
    @Operation(
            summary = "Deactivate a user account",
            description = "Deactivate a user account by setting its status to INACTIVE. This endpoint requires the user's ID."
    )
    public ResponseEntity<Void> deactivateUser(@PathVariable Long userId) {
        appUserCommandService.deactivateUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}/status")
    @Operation(
            summary = "Change the status of a user",
            description = "Change the status of a user to ACTIVE, INACTIVE, or any other supported status. The new status is provided as a query parameter."
    )
    public ResponseEntity<AppUserDto> changeStatus(@PathVariable Long userId, @RequestParam AuthUserStatus status) {
        AppUserDto appUserDto = appUserCommandService.changeUserStatus(userId, status);
        return ResponseEntity.ok(appUserDto);
    }
}
