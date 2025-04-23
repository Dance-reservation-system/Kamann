package pl.kamann.infrastructure.auth.cookie;

import jakarta.servlet.http.Cookie;

public class RefreshTokenCookieFactory {

    public static Cookie create(String refreshToken) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/api/v1/auth/refresh-token");
        cookie.setMaxAge(60 * 60 * 24);
        return cookie;
    }
}