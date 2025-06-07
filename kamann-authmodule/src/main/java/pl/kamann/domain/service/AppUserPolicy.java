package pl.kamann.domain.service;

public interface AppUserPolicy {

    void ensureValidProfile(
            String firstName,
            String lastName,
            String phone);
}
