package pl.kamann.dtos;

import jakarta.validation.constraints.Email;
import lombok.Builder;

@Builder
public record UserDetailsDto(
        @Email
        String email,
        String phone,
        String firstName,
        String lastName
) {
}
