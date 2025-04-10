package pl.kamann.dtos;

import lombok.Builder;

@Builder
public record UserDetailsDto(
        String email,
        String phone,
        String firstName,
        String lastName
) {
}
