package pl.kamann.application.authuser.lookup;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.domain.authuser.vo.StatusCode;
import shared.ApiException;

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
                    StatusCode.NO_RESULTS.name());
        };
    }
}