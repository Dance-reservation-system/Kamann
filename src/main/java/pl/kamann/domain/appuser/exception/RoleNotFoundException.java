package pl.kamann.domain.appuser.exception;

import org.springframework.http.HttpStatus;
import pl.kamann.domain.authuser.AuthCodes;
import pl.kamann.infrastructure.handler.ApiException;

public class RoleNotFoundException extends ApiException {
    public RoleNotFoundException() {
        super("Role not found.", HttpStatus.NOT_FOUND, AuthCodes.ROLE_NOT_FOUND.name());
    }
}