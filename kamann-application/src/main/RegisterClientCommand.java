package main;

/**
 * Command object representing a client registration request.
 */
public record RegisterClientCommand(
        String email,
        String password,
        String firstName,
        String lastName,
        String phone
) {}
