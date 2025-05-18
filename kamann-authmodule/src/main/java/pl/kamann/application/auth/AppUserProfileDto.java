package pl.kamann.application.auth;

import pl.kamann.domain.vo.AuthUserStatus;

import java.time.LocalDateTime;
import java.util.UUID;

record AppUserProfileDto(
    UUID id,
    String username,
    String email,
    AuthUserStatus status,
    LocalDateTime registeredAt,
    String role
) {}