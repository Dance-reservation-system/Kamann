package pl.kamann.application.auth.command;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import pl.kamann.domain.service.AppUserPolicy;

public record RegisterInstructorRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        @NotBlank String firstName,
        @NotBlank String lastName,
        @Pattern(regexp = "\\d{9}") String phone,
        @NotNull AppUserPolicy policy
) {}
