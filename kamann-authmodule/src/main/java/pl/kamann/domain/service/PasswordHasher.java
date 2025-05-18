package pl.kamann.domain.service;

/**
 * Ubiquitous Language Summary:
 * Contract for password hashing and verification used in user authentication.
 */
public interface PasswordHasher {
    boolean matches(String rawPassword, String encodedPassword);

    String hash(String rawPassword);
}
