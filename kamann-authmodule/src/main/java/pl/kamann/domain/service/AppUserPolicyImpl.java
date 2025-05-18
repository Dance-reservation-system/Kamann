package pl.kamann.domain.service;

import org.springframework.stereotype.Component;

@Component
public class AppUserPolicyImpl implements AppUserPolicy {

    @Override
    public void ensureValidProfile(String firstName, String lastName, String phone) {
        if (firstName == null || firstName.isBlank()) {
            throw new IllegalArgumentException("First name cannot be blank");
        }

        if (lastName == null || lastName.isBlank()) {
            throw new IllegalArgumentException("Last name cannot be blank");
        }

        if (phone != null && !phone.matches("\\+?[0-9\\- ]{7,15}")) {
            throw new IllegalArgumentException("Phone number format is invalid");
        }
    }
}