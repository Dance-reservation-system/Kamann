package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginResponse;

@Service
@RequiredArgsConstructor
class AuthQueryServiceImpl implements AuthQueryService {

    // inject whatever you need, e.g.:
    // private final JwtTokenProvider tokenProvider;
    // private final AppUserQueryService    userQueryService;

    @Override
    public LoginResponse refreshToken(String refreshToken, HttpServletResponse response) {
        // 1) validate the incoming refreshToken
        // 2) generate a new access token (and maybe a new refresh token)
        // 3) set cookies/headers on the HttpServletResponse
        // 4) return a LoginResponse DTO containing new tokens
        throw new UnsupportedOperationException("TODO: implement refresh logic");
    }

    @Override
    public AppUserDto getCurrentUser(HttpServletRequest request) {
       return null;
    }
}
