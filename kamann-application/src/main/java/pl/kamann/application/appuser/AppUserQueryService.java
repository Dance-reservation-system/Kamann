/**
 * Ubiquitous Language Summary:
 * Application service responsible for read-only operations on user data,
 * such as fetching user profiles, filtering by roles, and supporting pagination.
 */
package pl.kamann.application.appuser;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.lookup.AppUserFinder;
import pl.kamann.application.authuser.lookup.RoleLookupService;
import pl.kamann.application.shared.pagination.PaginatedResponseDto;
import pl.kamann.application.shared.pagination.PaginationMetaData;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.port.out.AuthUserRepository;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Role;
import pl.kamann.security.jwt.JwtUtils;
import shared.dto.PaginationCriteria;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AppUserQueryService {

    private final AppUserMapper appUserMapper;
    private final AppUserFinder appUserFinder;
    private final RoleLookupService roleLookupService;
    private final AuthUserRepository authUserRepository;
    private final JwtUtils jwtUtils;

    public PaginatedResponseDto<AppUserDto> getUsers(PaginationCriteria criteria, String roleName) {
        criteria = new PaginationCriteria(criteria.getPage(), criteria.getSize(), null, null);

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
        AppUser appUser = appUserFinder.findAppUserByAuthUser(authUser);
        return appUserMapper.toAppUserDto(appUser);
    }

    @Transactional(readOnly = true)
    public AppUserProfileDto getLoggedInUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        jwtUtils.validateToken(token);

        Email email = new Email(jwtUtils.getSubject(token));
        AuthUser authUser = authUserRepository
                .findByEmail(email)
                .orElseThrow(() ->
                        new IllegalStateException("AuthUser not found: " + email.value())
                );

        var appUser = appUserFinder.findAppUserByAuthUser(authUser);
        return appUserMapper.toProfileDto(appUser);
    }
}