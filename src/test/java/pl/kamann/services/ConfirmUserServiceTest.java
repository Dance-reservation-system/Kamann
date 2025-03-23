package pl.kamann.services;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.exception.handler.ExceptionHandlerService;
import pl.kamann.config.exception.services.UserLookupService;
import pl.kamann.config.exception.services.ValidationService;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.Role;
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.email.EmailSender;

import java.util.List;
import java.util.Locale;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class ConfirmUserServiceTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private ExceptionHandlerService exceptionHandlerService;

    @Mock
    private TokenService tokenService;

    @Mock
    private AppUserRepository appUserRepository;

    @Mock
    private AuthUserRepository authUserRepository;

    @InjectMocks
    private ConfirmUserService confirmUserService;

    @Mock
    private EmailSender emailSender;

    @Mock
    private UserLookupService userLookupService;

    @Mock
    private ValidationService validationService;

    @Test
    public void shouldConfirmAccount() {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        when(jwtUtils.validateToken(anyString(), any(TokenType.class))).thenReturn(true);
        when(jwtUtils.extractEmail(anyString())).thenReturn(email);
        when(userLookupService.findUserByEmail(email)).thenReturn(appUser);
        when(appUserRepository.existsByAuthUser(authUser)).thenReturn(false);

        when(appUserRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        confirmUserService.confirmUserAccount("valid_token");

        verify(authUserRepository).save(authUser);
    }


    @Test
    public void shouldHandleInvalidToken() {
        String invalidToken = "invalid_token";
        TokenType tokenType = TokenType.CONFIRMATION;
        when(jwtUtils.validateToken(invalidToken, tokenType)).thenReturn(false);

        ApiException apiException = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount(invalidToken)
        );

        assertEquals("Invalid confirmation token.", apiException.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, apiException.getStatus());
        assertEquals(AuthCodes.INVALID_TOKEN.name(), apiException.getCode());
    }

    @Test
    public void shouldHandleUserNotFound() {
        String validToken = "valid_token";
        String email = "user@example.com";

        when(jwtUtils.validateToken(validToken, TokenType.CONFIRMATION)).thenReturn(true);
        when(jwtUtils.extractEmail(validToken)).thenReturn(email);
        when(userLookupService.findUserByEmail(email)).thenReturn(null);

        ApiException exception = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount(validToken)
        );

        assertEquals("User not found", exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
        assertEquals(AuthCodes.USER_NOT_FOUND.name(), exception.getCode());
    }

    @Test
    public void shouldNotSendConfirmationEmailIfUserAlreadyConfirmed() {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);
        authUser.setRoles(Set.of(new Role("CLIENT")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        confirmUserService.sendConfirmationEmail(authUser);

        verify(emailSender, times(0))
                .sendEmail(eq(authUser.getEmail()), anyString(), any(), eq("client.registration"));
    }

    @Test
    public void shouldConfirmAccountIfUserIsDisabled() {
        String validToken = "valid_token";
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        when(jwtUtils.validateToken(validToken, TokenType.CONFIRMATION)).thenReturn(true);
        when(jwtUtils.extractEmail(validToken)).thenReturn(email);
        when(userLookupService.findUserByEmail(email)).thenReturn(appUser);
        when(authUserRepository.save(authUser)).thenReturn(authUser);

        confirmUserService.confirmUserAccount(validToken);

        verify(authUserRepository, times(1)).save(authUser);
        assertTrue(authUser.isEnabled());
    }

    @Test
    public void shouldNotConfirmAccountIfUserIsAlreadyEnabled() {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        when(jwtUtils.validateToken(anyString(), any(TokenType.class))).thenReturn(true);
        when(jwtUtils.extractEmail(anyString())).thenReturn(email);
        when(userLookupService.findUserByEmail(email)).thenReturn(appUser);

        doThrow(new ApiException("User with email " + email + " is already confirmed",
                        HttpStatus.BAD_REQUEST,
                        AuthCodes.USER_ALREADY_CONFIRMED.name()))
                .when(exceptionHandlerService).handleUserAlreadyConfirmedException(email);

        ApiException exception = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount("valid_token")
        );

        assertEquals("User with email " + email + " is already confirmed", exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(AuthCodes.USER_ALREADY_CONFIRMED.name(), exception.getCode());

        verify(exceptionHandlerService).handleUserAlreadyConfirmedException(email);
    }

    @Test
    public void shouldSendConfirmationEmailToAdminIfUserIsInstructor() {
        String email = "instructor@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);
        authUser.setRoles(Set.of(new Role("INSTRUCTOR")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        AuthUser adminUser = new AuthUser();
        adminUser.setEmail("admin@example.com");

        when(authUserRepository.findAdminUser()).thenReturn(List.of(adminUser));

        confirmUserService.sendConfirmationEmail(authUser);
        verify(emailSender).sendEmail(adminUser.getEmail(), null, Locale.ENGLISH, "admin.approval");
        verify(emailSender).sendEmailWithoutConfirmationLink(eq(authUser.getEmail()), any(), eq("instructor.registration"));
    }

    @Test
    public void shouldSendConfirmationEmailToUserIfNotInstructor() {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);
        authUser.setRoles(Set.of(new Role("CLIENT")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        confirmUserService.sendConfirmationEmail(authUser);

        verify(emailSender).sendEmail(authUser.getEmail(), null, Locale.ENGLISH, "client.registration");
    }

    @Test
    public void shouldSendConfirmationSuccessEmailWhenAccountIsConfirmed(){
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        doNothing().when(emailSender).sendEmailWithoutConfirmationLink(anyString(), any(), eq("account.confirmed"));

        confirmUserService.sendConfirmationSuccessEmail(authUser);

        verify(emailSender, times(1)).sendEmailWithoutConfirmationLink(authUser.getEmail(), Locale.ENGLISH, "account.confirmed");
    }
}
