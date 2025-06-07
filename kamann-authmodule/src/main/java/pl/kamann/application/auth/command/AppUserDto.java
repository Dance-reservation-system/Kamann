package pl.kamann.application.auth.command;

import java.util.UUID;

public record AppUserDto(
        UUID id,
        String email,
        String firstName,
        String lastName,
        String status,
        String phone
) {}