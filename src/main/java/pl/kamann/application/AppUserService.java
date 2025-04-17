package pl.kamann.application;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.domain.appuser.*;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.user.UserAccountService; // Nowa zależność
import pl.kamann.infrastructure.handler.ApiException;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationMetaData;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;

@Service
@RequiredArgsConstructor
public class AppUserService {

    private final AppUserRepository appUserRepository;
    private final AppUserMapper appUserMapper;
    private final UserLookupService userLookupService;
    private final RoleLookupService roleLookupService;
    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;
    private final AuthUserRepository authUserRepository;
    private final UserAccountService userAccountService; // Wstrzykujemy domenową usługę zarządzania kontami

    public PaginatedResponseDto<AppUserDto> getUsers(Pageable pageable, String roleName) {
        pageable = paginationService.validatePageable(pageable);

        Page<AuthUser> pagedAuthUsers;

        if (roleName == null || roleName.isEmpty()) {
            pagedAuthUsers = authUserRepository.findAll(pageable);
        } else {
            Role role = roleLookupService.findRoleByName(roleName);
            pagedAuthUsers = authUserRepository.findUsersByRoleWithRoles(pageable, role);
        }

        return paginationUtil.toPaginatedResponse(pagedAuthUsers, this::mapAuthUserToAppUserDto);
    }

    private AppUserDto mapAuthUserToAppUserDto(AuthUser authUser) {
        AppUser appUser = userLookupService.findAppUserByAuthUser(authUser);
        return appUserMapper.toAppUserDto(appUser);
    }

    public AppUserDto getUserById(Long id) {
        AppUser user = userLookupService.findUserById(id);
        return appUserMapper.toAppUserDto(user);
    }

    @Transactional
    public AppUserDto changeUserStatus(Long userId, AuthUserStatus status) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        AuthUser authUser = user.getAuthUser();
        userAccountService.changeStatus(authUser, status); // Używamy domenowej usługi
        // appUserRepository.save(user); // Zmiany statusu AuthUser są już zapisywane w UserAccountService

        return appUserMapper.toAppUserDto(user);
    }

    public void activateUser(Long userId) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        userAccountService.activate(user.getAuthUser());
    }

    public void deactivateUser(Long userId) {
        AppUser user = userLookupService.findUserByIdWithAuth(userId);
        userAccountService.deactivate(user.getAuthUser());
    }

    public PaginatedResponseDto<AppUserDto> getUsersByRole(String roleName, Pageable pageable) {
        Role role = roleLookupService.findRoleByName(roleName);

        Page<AuthUser> authUsers = authUserRepository.findByRolesContaining(role, pageable);
        Page<AppUser> users = authUsers.map(AuthUser::getAppUser);

        PaginationMetaData metaData = new PaginationMetaData(users.getTotalPages(), users.getTotalElements());

        return paginationUtil.toPaginatedResponseDto(new PaginatedResponseDto<>(users.getContent(), metaData));
    }
}