package pl.kamann.application;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthQueryService {
    LoginResponse refreshToken(String refreshToken, HttpServletResponse response);
    AppUserDto getCurrentUser(HttpServletRequest request);
}