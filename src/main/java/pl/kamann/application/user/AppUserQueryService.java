/**
 * Ubiquitous Language Summary:
 * Application service responsible for read-only operations on user data,
 * such as fetching user profiles, filtering by roles, and supporting pagination.
 */
package pl.kamann.application.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.lookup.RoleLookupService;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.common.PaginationCriteria;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationMetaData;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AppUserQueryService {

    private final AppUserMapper appUserMapper;
    private final UserLookupService userLookupService;
    private final RoleLookupService roleLookupService;
    private final AuthUserRepository authUserRepository;

    public PaginatedResponseDto<AppUserDto> getUsers(PaginationCriteria criteria, String roleName) {
        criteria = new PaginationCriteria(criteria.page(), criteria.size());

        List<AuthUser> authUsers;
        long total;

        if (roleName == null || roleName.isEmpty()) {
            authUsers = authUserRepository.findAll(criteria);
            total = authUserRepository.count();
        } else {
            Role role = roleLookupService.findRoleByName(roleName);
            authUsers = authUserRepository.findByRolesContaining(role, criteria);
            total = authUserRepository.countByRole(role);
        }

        List<AppUserDto> userDtos = authUsers.stream()
                .map(this::mapAuthUserToAppUserDto)
                .toList();

        PaginationMetaData meta = PaginationMetaData.from(criteria, total);
        return new PaginatedResponseDto<>(userDtos, meta);
    }

    private AppUserDto mapAuthUserToAppUserDto(AuthUser authUser) {
        AppUser appUser = userLookupService.findAppUserByAuthUser(authUser);
        return appUserMapper.toAppUserDto(appUser);
    }
}