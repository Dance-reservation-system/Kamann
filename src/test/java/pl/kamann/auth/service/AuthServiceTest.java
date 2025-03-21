package pl.kamann.auth.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.codes.RoleCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.services.RoleLookupService;
import pl.kamann.config.exception.services.ValidationService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.dtos.AppUserDto;
import pl.kamann.dtos.login.LoginRequest;
import pl.kamann.dtos.login.LoginResponse;
import pl.kamann.dtos.register.RegisterRequest;
import pl.kamann.entities.appuser.*;
import pl.kamann.mappers.AppUserMapper;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.repositories.RoleRepository;
import pl.kamann.services.AuthService;
import pl.kamann.services.ConfirmUserService;
import pl.kamann.services.RefreshTokenService;
import pl.kamann.services.factory.UserFactory;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Slf4j
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private ValidationService validationService;

    @Mock
    private AppUserRepository appUserRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private ConfirmUserService confirmUserService;

    @Mock
    private UserFactory userFactory;

    @Mock
    private AppUserMapper appUserMapper;

    @Mock
    private RoleLookupService roleLookupService;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthService authService;

    private Role clientRole;

    @BeforeEach
    void setUp() {
        clientRole = new Role();
        clientRole.setName("CLIENT");
    }

    @Test
    void shouldLoginSuccessfully() {
        LoginRequest loginRequest = new LoginRequest("user@example.com", "password");
        AuthUser user = AuthUser.builder()
                .email(loginRequest.email())
                .password("encodedPassword")
                .roles(Set.of(clientRole))
                .enabled(true)
                .build();

        Authentication mockAuthentication = new UsernamePasswordAuthenticationToken(user, "encodedPassword", user.getAuthorities());
        String generatedAccessToken = "accessToken";
        String generatedRefreshToken = "refreshToken";

        Map<String, Object> claims = jwtUtils.createClaims("roles", user.getRoles().stream().map(Role::getName).toList());

        when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(mockAuthentication);
        when(jwtUtils.generateToken(loginRequest.email(), claims)).thenReturn(generatedAccessToken);
        when(refreshTokenService.generateRefreshToken(user)).thenReturn(generatedRefreshToken);

        LoginResponse response = authService.login(loginRequest, httpServletResponse);

        assertNotNull(response);
        assertEquals(generatedAccessToken, response.token());

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        verify(httpServletResponse).addCookie(cookieCaptor.capture());

        Cookie refreshTokenCookie = cookieCaptor.getAllValues().getFirst();

        assertEquals("refresh_token", refreshTokenCookie.getName());
        assertEquals(generatedRefreshToken, refreshTokenCookie.getValue());
        assertTrue(refreshTokenCookie.isHttpOnly());

        verify(authenticationManager).authenticate(any(Authentication.class));
        verify(jwtUtils).generateToken(loginRequest.email(), claims);
        verify(refreshTokenService).generateRefreshToken(user);
        verify(httpServletResponse).addCookie(any());
    }

    @Test
    void shouldThrowExceptionWhenEmailIsNotEnabledDuringLogin() {
        LoginRequest loginRequest = new LoginRequest("user@example.com", "password");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new ApiException("Email not confirmed.", HttpStatus.UNAUTHORIZED, AuthCodes.EMAIL_NOT_CONFIRMED.getCode()));

        ApiException exception = assertThrows(ApiException.class, () -> authService.login(loginRequest, httpServletResponse));

        assertEquals("Email not confirmed.", exception.getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());

        verify(authenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    void shouldThrowExceptionWhenEmailNotFoundDuringLogin() {
        LoginRequest loginRequest = new LoginRequest("nonexistent@example.com", "password");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new ApiException("Invalid email address.", HttpStatus.NOT_FOUND, "INVALID_EMAIL"));

        ApiException exception = assertThrows(ApiException.class, () -> authService.login(loginRequest, httpServletResponse));

        assertEquals("Invalid email address.", exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());

        verify(authenticationManager).authenticate(any(Authentication.class));
    }

    @Test
    void shouldThrowExceptionWhenPasswordIsInvalidDuringLogin() {
        LoginRequest loginRequest = new LoginRequest("user@example.com", "wrongPassword");

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new ApiException("Invalid password.", HttpStatus.UNAUTHORIZED, "INVALID_PASSWORD"));

        ApiException exception = assertThrows(ApiException.class, () -> authService.login(loginRequest, httpServletResponse));

        assertEquals("Invalid password.", exception.getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());

        verify(authenticationManager).authenticate(any(Authentication.class));
        verifyNoInteractions(jwtUtils);
    }

    @Test
    void shouldRefreshTokenSuccessfully() {
        String oldRefreshToken = UUID.randomUUID().toString();
        String newRefreshToken = UUID.randomUUID().toString();
        String newAccessToken = "newAccessToken";

        AuthUser user = AuthUser.builder()
                .email("client@example.com")
                .roles(Set.of(clientRole))
                .build();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(oldRefreshToken);
        refreshToken.setAuthUser(user);

        Map<String, Object> claims = jwtUtils.createClaims("roles", user.getRoles());

        when(refreshTokenService.getRefreshToken(oldRefreshToken)).thenReturn(Optional.of(refreshToken));
        when(jwtUtils.generateToken(eq(user.getEmail()), eq(claims))).thenReturn(newAccessToken);
        when(refreshTokenService.generateRefreshToken(user)).thenReturn(newRefreshToken);

        LoginResponse response = authService.refreshToken(oldRefreshToken, httpServletResponse);

        assertNotNull(response);
        assertEquals(newAccessToken, response.token());

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        verify(httpServletResponse, times(2)).addCookie(cookieCaptor.capture());

        Cookie refreshTokenCookie = cookieCaptor.getAllValues().get(1);

        assertEquals("refresh_token", refreshTokenCookie.getName());
        assertEquals(newRefreshToken, refreshTokenCookie.getValue());
        assertTrue(refreshTokenCookie.isHttpOnly());

        verify(refreshTokenService).deleteRefreshToken(refreshToken);
        verify(refreshTokenService).generateRefreshToken(user);
        verify(httpServletResponse, times(2)).addCookie(any());
    }

    @Test
    void shouldThrowExceptionWhenRefreshTokenIsInvalid() {
        String invalidToken = "invalidToken";
        when(refreshTokenService.getRefreshToken(invalidToken)).thenReturn(Optional.empty());

        ApiException exception = assertThrows(ApiException.class, () -> authService.refreshToken(invalidToken, httpServletResponse));

        assertEquals("Invalid refresh token", exception.getMessage());
        assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatus());
    }

    @Test
    void shouldRegisterClientSuccessfully() {
        RegisterRequest request = new RegisterRequest("client@example.com", "password", "John", "Doe", "123-456-7890");

        AppUser savedUser = AppUser.builder()
                .id(1L)
                .firstName(request.firstName())
                .lastName(request.lastName())
                .phone(request.phone())
                .build();

        AuthUser savedAuthUser = AuthUser.builder()
                .id(2L)
                .email(request.email())
                .password("encodedPassword")
                .roles(Set.of(clientRole))
                .enabled(false)
                .status(AuthUserStatus.ACTIVE)
                .appUser(savedUser)
                .build();

        savedUser.setAuthUser(savedAuthUser);

        AppUserDto expectedDto = AppUserDto.builder()
                .id(savedUser.getId())
                .email(savedAuthUser.getEmail())
                .firstName(savedUser.getFirstName())
                .lastName(savedUser.getLastName())
                .phone(savedUser.getPhone())
                .status(savedAuthUser.getStatus().name())
                .build();

        when(userFactory.createAppUser(request)).thenReturn(savedUser);
        when(userFactory.createAndLinkAuthWithApp(request, clientRole, savedUser)).thenReturn(savedAuthUser);
        doNothing().when(validationService).validateEmailNotTaken(request.email());
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(invocation -> {
            AppUser user = invocation.getArgument(0);
            user.setId(1L);
            user.getAuthUser().setId(2L);
            return user;
        });
        when(roleLookupService.findRoleByName(any(String.class))).thenReturn(clientRole);
        when(appUserMapper.toAppUserDto(any(AppUser.class))).thenReturn(expectedDto);

        AppUserDto registeredUser = authService.registerClient(request);

        assertNotNull(registeredUser);
        assertEquals(expectedDto.id(), registeredUser.id());
        assertEquals(expectedDto.email(), registeredUser.email());
        assertEquals(expectedDto.firstName(), registeredUser.firstName());
        assertEquals(expectedDto.lastName(), registeredUser.lastName());
        assertEquals(expectedDto.phone(), registeredUser.phone());
        assertEquals(expectedDto.status(), registeredUser.status());

        verify(validationService).validateEmailNotTaken(request.email());
        verify(appUserRepository).save(any(AppUser.class));
        verify(appUserMapper).toAppUserDto(any(AppUser.class));
    }

    @Test
    void shouldThrowExceptionWhenEmailAlreadyRegisteredDuringRegistration() {
        RegisterRequest request = new RegisterRequest("existing@example.com", "password", "John", "Doe", "123-456-7890");

        doThrow(new ApiException("Email is already registered: " + request.email(), HttpStatus.CONFLICT, AuthCodes.EMAIL_ALREADY_EXISTS.getCode()))
                .when(validationService).validateEmailNotTaken(request.email());

        ApiException exception = assertThrows(ApiException.class, () -> authService.registerClient(request));

        assertEquals("Email is already registered: " + request.email(), exception.getMessage());
        assertEquals(HttpStatus.CONFLICT, exception.getStatus());

        verify(validationService).validateEmailNotTaken(request.email());
        verifyNoInteractions(passwordEncoder, roleRepository, appUserRepository);
    }

    @Test
    void shouldThrowExceptionWhenClientRoleNotFoundDuringRegistration() {
        RegisterRequest request = new RegisterRequest("new@example.com", "password", "John", "Doe", "123-456-7890");

        doNothing().when(validationService).validateEmailNotTaken(request.email());
        when(roleLookupService.findRoleByName(RoleCodes.CLIENT.name()))
                .thenThrow(new ApiException("Role not found: " + RoleCodes.CLIENT.name(), HttpStatus.NOT_FOUND, AuthCodes.ROLE_NOT_FOUND.getCode()));

        ApiException exception = assertThrows(ApiException.class, () -> authService.registerClient(request));

        assertEquals("Role not found: " + RoleCodes.CLIENT.name(), exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());

        verify(validationService).validateEmailNotTaken(request.email());
        verify(roleLookupService).findRoleByName(RoleCodes.CLIENT.name());
        verifyNoInteractions(passwordEncoder, appUserRepository, confirmUserService);
    }

    @Test
    void shouldThrowExceptionWhenInstructorRoleNotFoundDuringRegistration() {
        RegisterRequest request = new RegisterRequest("new@example.com", "password", "John", "Doe", "123-456-7890");

        doNothing().when(validationService).validateEmailNotTaken(request.email());
        when(roleLookupService.findRoleByName(RoleCodes.INSTRUCTOR.name()))
                .thenThrow(new ApiException("Role not found: " + RoleCodes.INSTRUCTOR.name(), HttpStatus.NOT_FOUND, AuthCodes.ROLE_NOT_FOUND.getCode()));

        ApiException exception = assertThrows(ApiException.class, () -> authService.registerInstructor(request));

        assertEquals("Role not found: " + RoleCodes.INSTRUCTOR.name(), exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());

        verify(validationService).validateEmailNotTaken(request.email());
        verify(roleLookupService).findRoleByName(RoleCodes.INSTRUCTOR.name());
        verifyNoInteractions(passwordEncoder, appUserRepository);
    }
}