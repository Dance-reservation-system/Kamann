package pl.kamann.domain.appuser.lookup;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.authuser.StatusCodes;
import pl.kamann.infrastructure.handler.ApiException;

@Service
public class RoleLookupService {

    public Role findRoleByName(String roleName) {
        String upper = roleName == null ? "" : roleName.trim().toUpperCase();
        return switch (upper) {
            case "ADMIN"      -> Role.ADMIN;
            case "INSTRUCTOR" -> Role.INSTRUCTOR;
            case "CUSTOMER"   -> Role.CUSTOMER;
            default -> throw new ApiException(
                    "Role not found: " + roleName,
                    HttpStatus.NOT_FOUND,
                    StatusCodes.NO_RESULTS.name());
        };
    }
}