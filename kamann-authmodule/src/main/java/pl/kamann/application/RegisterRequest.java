package pl.kamann.application;

public record RegisterRequest(
        String firstName,
        String lastName,
        String phone,
        String email,
        String password
) {
}