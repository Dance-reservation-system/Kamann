package pl.kamann.services;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.pagination.PaginatedResponseDto;
import pl.kamann.config.pagination.PaginationMetaData;
import pl.kamann.dtos.AppUserDto;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.Role;
import pl.kamann.mappers.AppUserMapper;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.utility.EntityLookupService;
import pl.kamann.config.pagination.PaginationService;
import pl.kamann.config.pagination.PaginationUtil;

@Service
@RequiredArgsConstructor
public class AppUserService implements UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final AppUserMapper appUserMapper;

    private final EntityLookupService entityLookupService;

    private final PaginationService paginationService;
    private final PaginationUtil paginationUtil;
    private final AuthUserRepository authUserRepository;


    public PaginatedResponseDto<AppUserDto> getUsers(Pageable pageable, String roleName) {
        pageable = paginationService.validatePageable(pageable);

        Page<AuthUser> pagedAuthUsers;

        if (roleName == null || roleName.isEmpty()) {
            pagedAuthUsers = authUserRepository.findAll(pageable);
        } else {
            Role role = entityLookupService.findRoleByName(roleName);
            pagedAuthUsers = authUserRepository.findUsersByRoleWithRoles(pageable, role);
        }

        return paginationUtil.toPaginatedResponse(pagedAuthUsers, this::mapAuthUserToAppUserDto);
    }

    private AppUserDto mapAuthUserToAppUserDto(AuthUser authUser) {
        AppUser appUser = entityLookupService.findAppUserByAuthUser(authUser);
        return appUserMapper.toAppUserDto(appUser);
    }

    public AppUserDto getUserById(Long id) {
        AppUser user = entityLookupService.findUserById(id);
        return appUserMapper.toAppUserDto(user);
    }


    @Transactional
    public AppUserDto changeUserStatus(Long userId, AuthUserStatus status) {
        entityLookupService.validateUserId(userId);
        entityLookupService.validateUserStatus(status);

        AppUser user = entityLookupService.findUserByIdWithAuth(userId);
        AuthUser authUser = user.getAuthUser();
        authUser.setStatus(status);
        appUserRepository.save(user);

        return appUserMapper.toAppUserDto(user);
    }

    public void activateUser(Long userId) {
        changeUserStatus(userId, AuthUserStatus.ACTIVE);
    }

    public void deactivateUser(Long userId) {
        changeUserStatus(userId, AuthUserStatus.INACTIVE);
    }

    public PaginatedResponseDto<AppUserDto> getUsersByRole(String roleName, Pageable pageable) {
        Role role = entityLookupService.findRoleByName(roleName);

        Page<AuthUser> authUsers = authUserRepository.findByRolesContaining(role, pageable);
        Page<AppUser> users = authUsers.map(AuthUser::getAppUser);

        PaginationMetaData metaData = new PaginationMetaData(users.getTotalPages(), users.getTotalElements());

        return appUserMapper.toPaginatedResponseDto(new PaginatedResponseDto<>(users.getContent(), metaData));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return authUserRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}