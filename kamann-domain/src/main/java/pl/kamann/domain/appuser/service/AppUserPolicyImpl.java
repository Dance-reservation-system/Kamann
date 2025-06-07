package pl.kamann.domain.appuser.service;

import org.springframework.stereotype.Component;

/**
 * Default implementation of AppUserPolicy.
 */
@Component
public class AppUserPolicyImpl implements AppUserPolicy {

    @Override
    public void ensureValidProfile(String firstName, String lastName, String phone) {
        // example rule: names must be non-empty
        if (firstName == null || firstName.trim().isEmpty()) {
            throw new IllegalArgumentException("First name must not be empty");
        }
        if (lastName == null || lastName.trim().isEmpty()) {
            throw new IllegalArgumentException("Last name must not be empty");
        }
        // example rule: phone must be 7–15 digits, optional leading '+'
        if (phone == null || !phone.matches("^\\+?[0-9]{7,15}$")) {
            throw new IllegalArgumentException("Phone must be a valid number: " + phone);
        }
    }
}