package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.StatusCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.dtos.UserDetailsDto;
import pl.kamann.entities.appuser.AppUser;

@RequiredArgsConstructor
@Service
public class AccountValidationService {

    public void validateUpdate(UserDetailsDto requestDto, AppUser appUser) {
        validateUserFirstName(requestDto.firstName());
        validateUserLastName(requestDto.lastName());
        validatePhone(requestDto.phone());
    }

    public void validateUserFirstName(String userFirstName) {
        if (userFirstName.length() > 30) {
            throw new ApiException(
                    "User First Name must have under 30 letters",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }
    }

    public void validateUserLastName(String userLastName) {
        if (userLastName.length() > 30) {
            throw new ApiException(
                    "User Last Name must be under 30 letters",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }
    }

    public void validatePhone(String phone) {
        if(phone.length() > 9) {
            throw new ApiException(
                    "User Phone must be under 9 letters",
                    HttpStatus.BAD_REQUEST,
                    StatusCodes.INVALID_INPUT.name()
            );
        }
    }
}