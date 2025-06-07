package pl.kamann.application.auth.command;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        String fullName)
{}