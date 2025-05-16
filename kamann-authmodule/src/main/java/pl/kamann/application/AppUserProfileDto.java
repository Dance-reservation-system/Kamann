package pl.kamann.application;

import java.time.LocalDateTime;
import java.util.UUID;

public record AppUserProfileDto(
    UUID id,
    String username,
    String email,
    AuthUserStatus status,
    LocalDateTime registeredAt,
    String role
) {}