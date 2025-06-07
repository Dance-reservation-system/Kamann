package pl.kamann.application.appuser;

import pl.kamann.domain.authuser.vo.AuthUserStatus;

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