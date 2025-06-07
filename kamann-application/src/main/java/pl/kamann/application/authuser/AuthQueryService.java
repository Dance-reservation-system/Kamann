package pl.kamann.application.authuser;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import shared.LoginResponse;
import pl.kamann.application.appuser.AppUserDto;

public interface AuthQueryService {
    LoginResponse refreshToken(String refreshToken, HttpServletResponse response);
    AppUserDto getCurrentUser(HttpServletRequest request);
}