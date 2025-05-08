package pl.kamann.application.appuser;

import pl.kamann.domain.authuser.vo.AuthUserStatus;

import java.time.LocalDateTime;


public record AppUserProfileDto(
    Long id,
    String username,
    String email,
    AuthUserStatus status,
    LocalDateTime registeredAt,
    String role
) {}