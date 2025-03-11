package pl.kamann.user.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.kamann.config.codes.RoleCodes;
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
import pl.kamann.repositories.RoleRepository;
import pl.kamann.services.AppUserService;
import pl.kamann.services.factory.UserFactory;
import pl.kamann.utility.EntityLookupService;
import pl.kamann.config.pagination.PaginationService;
import pl.kamann.config.pagination.PaginationUtil;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AppUserServiceTest {

    @Mock
    private AppUserRepository appUserRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AppUserMapper appUserMapper;

    @Mock
    private EntityLookupService entityLookupService;

    @Mock
    private PaginationService paginationService;

    @Mock
    private PaginationUtil paginationUtil;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserFactory userFactory;

    @InjectMocks
    private AppUserService appUserService;

    @Test
    void getAllUsersReturnsPaginatedResponseDto() {
        Role clientRole = new Role("CLIENT");
        Role instructorRole = new Role("INSTRUCTOR");

        AuthUser authUser1 = AuthUser.builder()
                .email("email1@example.com")
                .roles(Set.of(clientRole))
                .status(AuthUserStatus.ACTIVE)
                .build();
        AppUser user1 = AppUser.builder()
                .id(1L)
                .firstName("John")
                .lastName("Doe")
                .authUser(authUser1)
                .build();
        authUser1.setAppUser(user1);

        AuthUser authUser2 = AuthUser.builder()
                .email("email2@example.com")
                .roles(Set.of(instructorRole))
                .status(AuthUserStatus.INACTIVE)
                .build();
        AppUser user2 = AppUser.builder()
                .id(2L)
                .firstName("Jane")
                .lastName("Smith")
                .authUser(authUser2)
                .build();
        authUser2.setAppUser(user2);

        var authUsers = List.of(authUser1, authUser2);
        int size = authUsers.size();
        Pageable pageable = PageRequest.of(0, size);
        Page<AuthUser> pagedAuthUsers = new PageImpl<>(authUsers, pageable, size);

        when(paginationService.validatePageable(pageable)).thenReturn(pageable);

        when(authUserRepository.findAll(pageable)).thenReturn(pagedAuthUsers);

        List<AppUserDto> appUserDtos = authUsers.stream()
                .map(AuthUser::getAppUser)
                .map(appUser -> new AppUserDto(
                        appUser.getId(),
                        appUser.getFirstName(),
                        appUser.getLastName(),
                        appUser.getAuthUser().getEmail(),
                        appUser.getAuthUser().getStatus().name(),
                        appUser.getAuthUser().getRoles().stream().findFirst().map(Role::getName).orElse(null)
                ))
                .toList();

        PaginatedResponseDto<AppUserDto> expectedResponse = new PaginatedResponseDto<>(
                appUserDtos,
                new PaginationMetaData(1, size)
        );

        doReturn(expectedResponse).when(paginationUtil).toPaginatedResponse(
                eq(pagedAuthUsers),
                any(Function.class)
        );

        var result = appUserService.getUsers(pageable, null);

        // Assertions
        assertNotNull(result);
        assertEquals(size, result.getMetaData().getTotalElements());
        assertEquals(1, result.getMetaData().getTotalPages());

        verify(paginationService).validatePageable(pageable);
        verify(authUserRepository).findAll(pageable);
        verify(paginationUtil).toPaginatedResponse(eq(pagedAuthUsers), any(Function.class));
    }

    @Test
    void getUserByIdReturnsUserDto() {
        Long userId = 1L;
        AuthUser authUser = AuthUser.builder()
                .email("email@example.com")
                .roles(Set.of(new Role("CLIENT")))
                .status(AuthUserStatus.ACTIVE)
                .build();
        AppUser user = AppUser.builder()
                .id(userId)
                .firstName("Test")
                .lastName("User")
                .authUser(authUser)
                .build();
        authUser.setAppUser(user);

        when(entityLookupService.findUserById(userId)).thenReturn(user);
        var userDto = new AppUserDto(userId, authUser.getEmail(), user.getFirstName(), user.getLastName(), authUser.getStatus().name(), user.getPhone());
        when(appUserMapper.toAppUserDto(user)).thenReturn(userDto);

        var result = appUserService.getUserById(userId);

        assertEquals(userDto, result);
        verify(entityLookupService).findUserById(userId);
        verify(appUserMapper).toAppUserDto(user);
    }

    @Test
    void activateUserChangesStatusToActive() {
        Long userId = 1L;

        AuthUser authUser = AuthUser.builder()
                .status(AuthUserStatus.INACTIVE)
                .build();

        AppUser user = AppUser.builder()
                .id(userId)
                .authUser(authUser)
                .build();

        when(entityLookupService.findUserByIdWithAuth(userId)).thenReturn(user);
        when(appUserRepository.save(user)).thenReturn(user);

        appUserService.changeUserStatus(userId, AuthUserStatus.ACTIVE);

        assertEquals(AuthUserStatus.ACTIVE, authUser.getStatus());

        verify(entityLookupService).findUserByIdWithAuth(userId);
        verify(appUserRepository).save(user);
    }

    @Test
    void deactivateUserChangesStatusToInactive() {
        Long userId = 1L;
        AuthUser authUser = AuthUser.builder()
                .status(AuthUserStatus.ACTIVE)
                .build();
        AppUser user = AppUser.builder()
                .id(userId)
                .authUser(authUser)
                .build();

        when(entityLookupService.findUserByIdWithAuth(userId)).thenReturn(user);
        when(appUserRepository.save(user)).thenReturn(user);

        appUserService.changeUserStatus(userId, AuthUserStatus.INACTIVE);

        assertEquals(AuthUserStatus.INACTIVE, authUser.getStatus());

        verify(entityLookupService).findUserByIdWithAuth(userId);
        verify(appUserRepository).save(user);
    }

    @Test
    void getUsersByRoleReturnsEmptyResponseWhenNoUsersExist() {
        Pageable pageable = Pageable.unpaged();
        Role role = new Role(RoleCodes.INSTRUCTOR.name());

        when(entityLookupService.findRoleByName(role.getName())).thenReturn(role);
        when(authUserRepository.findByRolesContaining(role, pageable)).thenReturn(Page.empty(pageable));
        when(appUserMapper.toPaginatedResponseDto(any())).thenReturn(new PaginatedResponseDto<>(List.of(), new PaginationMetaData(0, 0)));

        var result = appUserService.getUsersByRole(role.getName(), pageable);

        assertNotNull(result);
        assertTrue(result.getContent().isEmpty());
        assertEquals(0, result.getMetaData().getTotalPages());
        assertEquals(0, result.getMetaData().getTotalElements());

        verify(authUserRepository).findByRolesContaining(role, pageable);
        verify(appUserMapper).toPaginatedResponseDto(any());
    }
}