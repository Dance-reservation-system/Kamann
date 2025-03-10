package pl.kamann.utility;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AttendanceCodes;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.codes.EventCodes;
import pl.kamann.config.codes.StatusCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.Role;
import pl.kamann.entities.event.Event;
import pl.kamann.entities.event.OccurrenceEvent;
import pl.kamann.repositories.*;

@Service
@RequiredArgsConstructor
public class EntityLookupService {

    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;
    private final EventRepository eventRepository;
    private final OccurrenceEventRepository occurrenceEventRepository;
    private final RoleRepository roleRepository;

    public AppUser findUserById(Long userId) {
        if (userId == null) {
            throw new ApiException(
                    "User ID cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }

        return appUserRepository.findById(userId)
                .orElseThrow(() -> new ApiException(
                        "User not found with ID: " + userId,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()
                ));
    }

    public Event findEventById(Long eventId) {
        return eventRepository.findById(eventId)
                .orElseThrow(() -> new ApiException(
                        "Event not found with ID: " + eventId,
                        HttpStatus.NOT_FOUND,
                        EventCodes.EVENT_NOT_FOUND.name()
                ));
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

    public AppUser findUserByEmail(String email) {
        return authUserRepository.findByEmail(email)
                .map(authUser -> {
                    AppUser appUser = authUser.getAppUser();
                    if (appUser == null) {
                        throw new ApiException(
                                "AppUser not found for AuthUser with email: " + email,
                                HttpStatus.NOT_FOUND,
                                AuthCodes.USER_NOT_FOUND.name());
                    }
                    return appUser;
                })
                .orElseThrow(() -> new ApiException(
                        "User not found with email: " + email,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));
    }

    public AppUser getLoggedInUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return findUserByEmail(email);
    }

    public OccurrenceEvent findOccurrenceEventByOccurrenceEventId(Long occurrenceEventId) {
        return occurrenceEventRepository.findById(occurrenceEventId)
                .orElseThrow(() -> new ApiException(
                        "OccurrenceEvent not found for ID: " + occurrenceEventId,
                        HttpStatus.NOT_FOUND,
                        AttendanceCodes.OCCURRENCE_EVENT_NOT_FOUND.name()
                ));
    }

    public Role findRoleByName(String roleName) {
        if (roleName == null || roleName.trim().isEmpty()) {
            throw new ApiException(
                    "Role name was not provided or is empty",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }

        return roleRepository.findByName(roleName.toUpperCase())
                .orElseThrow(() -> new ApiException(
                        "Role not found: " + roleName,
                        HttpStatus.NOT_FOUND,
                        StatusCodes.NO_RESULTS.name()));
    }

    public void validateUserIdAndStatus(Long userId, AuthUserStatus status) {
        if (userId == null) {
            throw new ApiException("User ID cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
        if (status == null) {
            throw new ApiException("Status cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public AppUser findUserByIdWithAuth(Long userId) {
        AppUser user = findUserById(userId);
        if (user == null) {
            throw new ApiException("User not found", HttpStatus.NOT_FOUND, StatusCodes.NO_RESULTS.name());
        }

        AuthUser authUser = user.getAuthUser();
        if (authUser == null) {
            throw new ApiException("Authentication data not found", HttpStatus.NOT_FOUND, AuthCodes.USER_NOT_FOUND.name());
        }

        return user;
    }

    public void handleInvalidTokenException() {
        throw new ApiException(
                "Invalid or expired confirmation Token",
                HttpStatus.UNAUTHORIZED,
                AuthCodes.INVALID_TOKEN.name()
        );
    }

    public void handleInvalidTokenTypeException() {
        throw new ApiException(
                "Token type is invalid",
                HttpStatus.UNAUTHORIZED,
                AuthCodes.INVALID_TOKEN.name()
        );
    }

    public void handleUserNotFoundException(String email) {
        throw new ApiException(
                "User not found with email: " + email,
                HttpStatus.NOT_FOUND,
                AuthCodes.USER_NOT_FOUND.name()
        );
    }

    public void handleUserAlreadyConfirmedException(String email) {
        throw new ApiException(
                "User with email " + email + " is already confirmed",
                HttpStatus.BAD_REQUEST,
                AuthCodes.USER_ALREADY_CONFIRMED.name()
        );
    }

    public void handleEmailSendingError() {
        throw new ApiException(
                "Error sending the confirmation email.",
                HttpStatus.INTERNAL_SERVER_ERROR,
                AuthCodes.CONFIRMATION_EMAIL_ERROR.name()
        );
    }

    public AppUser findAppUserByAuthUser(AuthUser authUser) {
        return appUserRepository.findByAuthUser(authUser)
                .orElseThrow(() -> new ApiException("AppUser not found for the given AuthUser",
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));
    }
}
