package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.codes.StatusCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.repositories.AuthUserRepository;

@RequiredArgsConstructor
@Service
public class ValidationService {

    private final AuthUserRepository authUserRepository;

    public void validateUserId(Long userId) {
        if (userId == null) {
            throw new ApiException(
                    "User ID cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public void validateUserStatus(AuthUserStatus status) {
        if (status == null) {
            throw new ApiException(
                    "Status cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public void validateAuthUser(AuthUser authUser) {
        if (authUser == null) {
           throw new ApiException(
                   "AuthUser not found",
                   HttpStatus.NOT_FOUND,
                   StatusCodes.NO_RESULTS.name());
        }
    }

    public void validateAppUser(AppUser appUser) {
        if (appUser == null) {
            throw new ApiException(
                    "AppUser not found",
                    HttpStatus.NOT_FOUND,
                    StatusCodes.NO_RESULTS.name());
        }
    }

    public void validateRoleName(String roleName) {
        if (roleName == null || roleName.trim().isEmpty()) {
            throw new ApiException(
                    "Role name was not provided or is empty",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public void validateEmailNotTaken(String email) {
        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new ApiException(
                    "Email is already registered: " + email,
                    HttpStatus.CONFLICT,
                    AuthCodes.EMAIL_ALREADY_EXISTS.name()
            );
        }
    }
}
