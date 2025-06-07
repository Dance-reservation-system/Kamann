package pl.kamann.application.authuser;

public record RegisterRequest(
    String firstName,
    String lastName,
    String phone,
    String email,
    String password
) {}