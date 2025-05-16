package pl.kamann.application;

public record RegisterClientCommand(
        String email,
        String password,
        String firstName,
        String lastName,
        String phone
) {
}
