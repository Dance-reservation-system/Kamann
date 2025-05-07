package pl.kamann.application.appuser;

/**
 * Ubiquitous Language Summary:
 * Lightweight representation of user details used in authentication responses.
 */
public record AppUserResponseDto(
    String email,
    String firstName,
    String lastName
) {}
