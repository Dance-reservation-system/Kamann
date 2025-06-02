package pl.kamann.application.auth.command;

public record LoginRequest(
        String email,
        String password
) {}