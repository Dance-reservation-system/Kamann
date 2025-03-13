package pl.kamann.config.exception.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.StatusCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.entities.appuser.Role;
import pl.kamann.repositories.RoleRepository;

@RequiredArgsConstructor
@Service
public class RoleLookupService {

    private final RoleRepository roleRepository;
    private final ValidationService validationService;

    public Role findRoleByName(String roleName) {
        validationService.validateRoleName(roleName);

        return roleRepository.findByName(roleName.toUpperCase())
                .orElseThrow(() -> new ApiException(
                        "Role not found: " + roleName,
                        HttpStatus.NOT_FOUND,
                        StatusCodes.NO_RESULTS.name()));
    }
}
