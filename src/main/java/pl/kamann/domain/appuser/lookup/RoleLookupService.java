package pl.kamann.domain.appuser.lookup;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.appuser.repository.RoleRepository;
import pl.kamann.domain.authuser.StatusCodes;
import pl.kamann.infrastructure.handler.ApiException;

@RequiredArgsConstructor
@Service
public class RoleLookupService {

    private final RoleRepository roleRepository;

    public Role findRoleByName(String roleName) {

        return roleRepository.findByName(roleName.toUpperCase())
                .orElseThrow(() -> new ApiException(
                        "Role not found: " + roleName,
                        HttpStatus.NOT_FOUND,
                        StatusCodes.NO_RESULTS.name()));
    }
}
