package pl.kamann.application.auth;

public interface PasswordHasher {
    boolean matches(String rawPassword, String encodedPassword);
    String encode(String rawPassword);
}