package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginResponse;

@Component
@RequiredArgsConstructor
public class AuthQueryFacade {

    private final AuthQueryService authQueryService;

    public LoginResponse refreshToken(String refreshToken, HttpServletResponse response) {
        return authQueryService.refreshToken(refreshToken, response);
    }

    public AppUserDto getCurrentUser(HttpServletRequest request) {
        return authQueryService.getCurrentUser(request);
    }
}
