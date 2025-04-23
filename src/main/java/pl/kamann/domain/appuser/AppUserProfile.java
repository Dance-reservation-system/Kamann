package pl.kamann.domain.appuser;

import java.util.Objects;

public record AppUserProfile(String firstName, String lastName, String phone) {

    public AppUserProfile {
        Objects.requireNonNull(firstName, "First name is required");
        Objects.requireNonNull(lastName, "Last name is required");

        if (firstName.isBlank()) {
            throw new IllegalArgumentException("First name cannot be blank");
        }

        if (lastName.isBlank()) {
            throw new IllegalArgumentException("Last name cannot be blank");
        }

        if (phone != null && phone.isBlank()) {
            throw new IllegalArgumentException("Phone cannot be blank if provided");
        }
    }

    public static AppUserProfile create(String firstName, String lastName, String phone) {
        return new AppUserProfile(firstName, lastName, phone);
    }

}