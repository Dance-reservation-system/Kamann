package pl.kamann.dtos;

import jakarta.validation.constraints.Email;
import lombok.Builder;

import java.util.Set;

@Builder
public record UserDetailsDto(
        @Email
        String email,
        String phone,
        String firstName,
        String lastName,
        Set<String> roles
) {
}
