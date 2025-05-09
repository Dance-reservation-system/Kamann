package pl.kamann.application.authuser.command;

public record RegisterClientCommand(
        String email,
        String password,
        String firstName,
        String lastName,
        String phone
) {}
