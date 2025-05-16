package pl.kamann.application;


public record LoginRequest(
    String email,

    String password
) {}