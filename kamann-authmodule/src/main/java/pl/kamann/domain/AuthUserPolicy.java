package pl.kamann.domain;

public interface AuthUserPolicy {
    void ensureEmailNotTaken(Email email);
    void ensureCanChangePassword(AuthUser authUser);
}