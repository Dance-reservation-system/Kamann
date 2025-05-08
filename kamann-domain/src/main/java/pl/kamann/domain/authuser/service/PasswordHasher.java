package pl.kamann.domain.authuser.service;

/**
 * Ubiquitous Language Summary:
 * Contract for password hashing and verification used in user authentication.
 */
public interface PasswordHasher {
    boolean matches(String rawPassword, String encodedPassword);
    String encode(String rawPassword);
}
