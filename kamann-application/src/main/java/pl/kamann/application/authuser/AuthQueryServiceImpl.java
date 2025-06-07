package pl.kamann.application.authuser;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import lombok.RequiredArgsConstructor;
import shared.LoginResponse;
import pl.kamann.application.appuser.AppUserDto;

@Service
@RequiredArgsConstructor
public class AuthQueryServiceImpl implements AuthQueryService {

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
        // 1) extract and validate the access token from the request (header / cookie)
        // 2) look up the AppUser via your domain/query service
        // 3) map it to AppUserDto and return
        throw new UnsupportedOperationException("TODO: implement getCurrentUser logic");
    }
}
