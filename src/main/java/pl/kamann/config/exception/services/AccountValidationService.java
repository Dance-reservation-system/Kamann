package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.StatusCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.Role;

import java.util.Set;

@RequiredArgsConstructor
@Service
public class AccountValidationService {

    private final ValidationService validationService;

    public void validateUpdateRequest(UserDetailsDto requestDto) {
        if (requestDto == null) {
            throw new ApiException(
                    "Request cannot be null",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }

        if (requestDto.firstName() != null) {
            validateUserFirstName(requestDto.firstName());
        }
        if (requestDto.lastName() != null) {
            validateUserLastName(requestDto.lastName());
        }
        if (requestDto.phone() != null) {
            validatePhone(requestDto.phone());
        }
        if (requestDto.email() != null) {
            validateEmail(requestDto.email());
        }
    }

    private void validateEmail(String email) {
        if (!isValidEmailFormat(email)) {
            throw new ApiException("Invalid email format",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }

        validationService.validateEmailNotTaken(email);
    }

    private boolean isValidEmailFormat(String email) {
        return email != null && email.matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$");
    }

    public void validateUserFirstName(String userFirstName) {
        if (userFirstName.length() > 30 || userFirstName.length() < 2) {
            throw new ApiException(
                    "User First Name must have more than 2 and less than 30 letters",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }
    }

    public void validateUserLastName(String userLastName) {
        if (userLastName.length() > 30 || userLastName.length() < 2) {
            throw new ApiException(
                    "User Last Name must have more than 2 and less than 30 letters",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }
    }

    public void validatePhone(String phone) {
        if (phone == null || phone.length() != 9 || !phone.matches("\\d+")) {
            throw new ApiException("Phone number must be exactly 9 digits",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public void validateClient(Set<Role> roles) {
        if(!roles.stream().getClass().getName().contains("CLIENT")) {
            throw new ApiException("User is not a Client",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }

    public void validateInstructor(Set<Role> roles) {
        if(!roles.stream().getClass().getName().contains("INSTRUCTOR")) {
            throw new ApiException("User is not a Client",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name());
        }
    }
}