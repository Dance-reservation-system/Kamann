package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.dto.LoginRequest;
import pl.kamann.domain.authuser.dto.LoginResponse;

@Service
@RequiredArgsConstructor
public class AuthSessionFacade {

    private final LoginUserService loginUserService;
    private final GetLoggedInUserService getLoggedInUserService;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        return loginUserService.login(request);
    }

    @Transactional(readOnly = true)
    public AppUserDto getLoggedInUser(HttpServletRequest request) {
        return getLoggedInUserService.getLoggedInUser(request);
    }
}