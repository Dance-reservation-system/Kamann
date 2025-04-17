package pl.kamann.domain.appuser;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.StatusCodes;
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.domain.authuser.ValidationService;

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
