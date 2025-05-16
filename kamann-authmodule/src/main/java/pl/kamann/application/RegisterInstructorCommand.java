package pl.kamann.application;


/**
 * Ubiquitous Language Summary:
 * Command object encapsulating all data required to register an instructor.
 */
public record RegisterInstructorCommand(
        String email,
        String password,
        String firstName,
        String lastName,
        String phone,
        AppUserPolicy policy
) {
}
