package pl.kamann.application;

public record LoginResponse(String accessToken, String email, String fullName) {}