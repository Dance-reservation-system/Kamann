package pl.kamann.application;

/**
 * Domain rules around AppUser profile creation and updates.
 */
public interface AppUserPolicy {
    /**
     * Ensure supplied names and phone meet business requirements.
     */
    void ensureValidProfile(String firstName, String lastName, String phone);
}
