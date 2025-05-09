package pl.kamann.web.auth;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.appuser.AppUserCommandService;
import pl.kamann.application.appuser.AppUserDto;
import pl.kamann.domain.authuser.vo.AuthUserStatus;

@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
class AdminUserCommandController {

    private final AppUserCommandService commandService;

    @PutMapping("/activate/{userId}")
    @Operation(summary = "Activate user", description = "Set a user’s status to ACTIVE")
    public ResponseEntity<Void> activate(@PathVariable Long userId) {
        commandService.activateUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/deactivate/{userId}")
    @Operation(summary = "Deactivate user", description = "Set a user’s status to INACTIVE")
    public ResponseEntity<Void> deactivate(@PathVariable Long userId) {
        commandService.deactivateUser(userId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}/status")
    @Operation(summary = "Change user status", description = "Change a user’s status to any supported value")
    public ResponseEntity<AppUserDto> changeStatus(
        @PathVariable Long userId,
        @RequestParam AuthUserStatus status
    ) {
        AppUserDto dto = commandService.changeUserStatus(userId, status);
        return ResponseEntity.ok(dto);
    }
}
