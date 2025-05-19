package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import pl.kamann.application.auth.command.AppUserDto;
import pl.kamann.application.auth.command.LoginResponse;

interface AuthQueryService {
    LoginResponse refreshToken(String refreshToken, HttpServletResponse response);
    AppUserDto getCurrentUser(HttpServletRequest request);
}