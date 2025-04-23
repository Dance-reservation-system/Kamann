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
import pl.kamann.application.user.AppUserCommandService;
import pl.kamann.application.user.AppUserQueryService;
import pl.kamann.domain.authuser.RoleCodes;
import pl.kamann.infrastructure.pagination.PaginatedResponseDto;
import pl.kamann.infrastructure.pagination.PaginationMetaData;
import pl.kamann.infrastructure.pagination.PaginationService;
import pl.kamann.infrastructure.pagination.PaginationUtil;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.appuser.Role;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.repository.AppUserRepository;
import pl.kamann.domain.authuser.AuthUserRepository;
import pl.kamann.domain.appuser.lookup.RoleLookupService;
import pl.kamann.domain.appuser.lookup.UserLookupService;

import java.util.List;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AppUserServiceTest {

//    @Mock
//    private AppUserRepository appUserRepository;
//
//    @Mock
//    private AuthUserRepository authUserRepository;
//
//    @Mock
//    private AppUserMapper appUserMapper;
//
//    @Mock
//    private PaginationService paginationService;
//
//    @Mock
//    private PaginationUtil paginationUtil;
//
//    @Mock
//    private UserLookupService userLookupService;
//
//    @Mock
//    private RoleLookupService roleLookupService;
//
//    @InjectMocks
//    private AppUserQueryService appUserQueryService;
//
//    @InjectMocks
//    private AppUserCommandService appUserCommandService;
//
//    @Test
//    void getAllUsersReturnsPaginatedResponseDto() {
//        Role clientRole = new Role("CLIENT");
//        Role instructorRole = new Role("INSTRUCTOR");
//
//        AuthUser authUser1 = AuthUser.builder()
//                .email("email1@example.com")
//                .roles(Set.of(clientRole))
//                .status(AuthUserStatus.ACTIVE)
//                .build();
//        AppUser user1 = AppUser.builder()
//                .id(1L)
//                .firstName("John")
//                .lastName("Doe")
//                .authUser(authUser1)
//                .build();
//        authUser1.setAppUser(user1);
//
//        AuthUser authUser2 = AuthUser.builder()
//                .email("email2@example.com")
//                .roles(Set.of(instructorRole))
//                .status(AuthUserStatus.INACTIVE)
//                .build();
//        AppUser user2 = AppUser.builder()
//                .id(2L)
//                .firstName("Jane")
//                .lastName("Smith")
//                .authUser(authUser2)
//                .build();
//        authUser2.setAppUser(user2);
//
//        var authUsers = List.of(authUser1, authUser2);
//        int size = authUsers.size();
//        Pageable pageable = PageRequest.of(0, size);
//        Page<AuthUser> pagedAuthUsers = new PageImpl<>(authUsers, pageable, size);
//
//        when(paginationService.validatePageable(pageable)).thenReturn(pageable);
//
//        when(authUserRepository.findAll(pageable)).thenReturn(pagedAuthUsers);
//
//        List<AppUserDto> appUserDtos = authUsers.stream()
//                .map(AuthUser::getAppUser)
//                .map(appUser -> new AppUserDto(
//                        appUser.getId(),
//                        appUser.getFirstName(),
//                        appUser.getLastName(),
//                        appUser.getAuthUser().getEmail(),
//                        appUser.getAuthUser().getStatus().name(),
//                        appUser.getAuthUser().getRoles().stream().findFirst().map(Role::getName).orElse(null)
//                ))
//                .toList();
//
//        PaginatedResponseDto<AppUserDto> expectedResponse = new PaginatedResponseDto<>(
//                appUserDtos,
//                new PaginationMetaData(1, size)
//        );
//
//        doReturn(expectedResponse).when(paginationUtil).toPaginatedResponse(
//                eq(pagedAuthUsers),
//                any(Function.class)
//        );
//
//        var result = appUserService.getUsers(pageable, null);
//
//        // Assertions
//        assertNotNull(result);
//        assertEquals(size, result.getMetaData().getTotalElements());
//        assertEquals(1, result.getMetaData().getTotalPages());
//
//        verify(paginationService).validatePageable(pageable);
//        verify(authUserRepository).findAll(pageable);
//        verify(paginationUtil).toPaginatedResponse(eq(pagedAuthUsers), any(Function.class));
//    }
//
//    @Test
//    void getUserByIdReturnsUserDto() {
//        Long userId = 1L;
//        AuthUser authUser = AuthUser.builder()
//                .email("email@example.com")
//                .roles(Set.of(new Role("CLIENT")))
//                .status(AuthUserStatus.ACTIVE)
//                .build();
//        AppUser user = AppUser.builder()
//                .id(userId)
//                .firstName("Test")
//                .lastName("User")
//                .authUser(authUser)
//                .build();
//        authUser.setAppUser(user);
//
//        when(userLookupService.findUserById(userId)).thenReturn(user);
//        var userDto = new AppUserDto(userId, authUser.getEmail(), user.getFirstName(), user.getLastName(), authUser.getStatus().name(), user.getPhone());
//        when(appUserMapper.toAppUserDto(user)).thenReturn(userDto);
//
//        var result = appUserService.getUserById(userId);
//
//        assertEquals(userDto, result);
//        verify(userLookupService).findUserById(userId);
//        verify(appUserMapper).toAppUserDto(user);
//    }
//
//    @Test
//    void activateUserChangesStatusToActive() {
//        Long userId = 1L;
//
//        AuthUser authUser = AuthUser.builder()
//                .status(AuthUserStatus.INACTIVE)
//                .build();
//
//        AppUser user = AppUser.builder()
//                .id(userId)
//                .authUser(authUser)
//                .build();
//
//        when(userLookupService.findUserByIdWithAuth(userId)).thenReturn(user);
//        when(appUserRepository.save(user)).thenReturn(user);
//
//        appUserService.changeUserStatus(userId, AuthUserStatus.ACTIVE);
//
//        assertEquals(AuthUserStatus.ACTIVE, authUser.getStatus());
//
//        verify(userLookupService).findUserByIdWithAuth(userId);
//        verify(appUserRepository).save(user);
//    }
//
//    @Test
//    void deactivateUserChangesStatusToInactive() {
//        Long userId = 1L;
//        AuthUser authUser = AuthUser.builder()
//                .status(AuthUserStatus.ACTIVE)
//                .build();
//        AppUser user = AppUser.builder()
//                .id(userId)
//                .authUser(authUser)
//                .build();
//
//        when(userLookupService.findUserByIdWithAuth(userId)).thenReturn(user);
//        when(appUserRepository.save(user)).thenReturn(user);
//
//        appUserService.changeUserStatus(userId, AuthUserStatus.INACTIVE);
//
//        assertEquals(AuthUserStatus.INACTIVE, authUser.getStatus());
//
//        verify(userLookupService).findUserByIdWithAuth(userId);
//        verify(appUserRepository).save(user);
//    }
//
//    @Test
//    void getUsersByRoleReturnsEmptyResponseWhenNoUsersExist() {
//        Pageable pageable = Pageable.unpaged();
//        Role role = new Role(RoleCodes.INSTRUCTOR.name());
//
//        when(roleLookupService.findRoleByName(role.getName())).thenReturn(role);
//        when(authUserRepository.findByRolesContaining(role, pageable)).thenReturn(Page.empty(pageable));
//        when(appUserMapper.toPaginatedResponseDto(any())).thenReturn(new PaginatedResponseDto<>(List.of(), new PaginationMetaData(0, 0)));
//
//        var result = appUserService.getUsersByRole(role.getName(), pageable);
//
//        assertNotNull(result);
//        assertTrue(result.getContent().isEmpty());
//        assertEquals(0, result.getMetaData().getTotalPages());
//        assertEquals(0, result.getMetaData().getTotalElements());
//
//        verify(authUserRepository).findByRolesContaining(role, pageable);
//        verify(appUserMapper).toPaginatedResponseDto(any());
//    }
}