package pl.kamann.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.kamann.application.auth.AuthQueryFacade;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginResponse;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
class AuthQueryController {

    private final AuthQueryFacade authFacade;

    @PostMapping("/refresh-token")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue("refresh_token") String refreshToken,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(authFacade.refreshToken(refreshToken, response));
    }

    @GetMapping("/me")
    public ResponseEntity<AppUserDto> me(HttpServletRequest request) {
        return ResponseEntity.ok(authFacade.getCurrentUser(request));
    }
}