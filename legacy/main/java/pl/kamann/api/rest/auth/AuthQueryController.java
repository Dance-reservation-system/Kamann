package pl.kamann.api.rest.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.auth.AuthQueryService;
import pl.kamann.application.user.dto.AppUserDto;
import pl.kamann.domain.authuser.dto.LoginResponse;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
class AuthQueryController {

    private final AuthQueryService authQueries;

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue("refresh_token") String refreshToken,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(
                authQueries.refreshToken(refreshToken, response)
        );
    }

    @GetMapping("/me")
    public ResponseEntity<AppUserDto> me(HttpServletRequest request) {
        return ResponseEntity.ok(authQueries.getCurrentUser(request));
    }
}
