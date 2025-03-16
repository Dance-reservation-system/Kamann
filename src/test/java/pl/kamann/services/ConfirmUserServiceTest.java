package pl.kamann.services;

import jakarta.mail.MessagingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
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
import pl.kamann.testcontainers.config.TestContainersConfig;

import java.util.Locale;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = {TestContainersConfig.class})
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

        Mockito.when(jwtUtils.validateToken(Mockito.anyString(), Mockito.any(TokenType.class))).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(Mockito.anyString())).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(appUser);
        Mockito.when(appUserRepository.existsByAuthUser(authUser)).thenReturn(false);

        Mockito.when(appUserRepository.save(Mockito.any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        confirmUserService.confirmUserAccount("valid_token");

        Mockito.verify(authUserRepository).save(authUser);
    }


    @Test
    public void shouldHandleInvalidToken() {
        String invalidToken = "invalid_token";
        TokenType tokenType = TokenType.CONFIRMATION;
        Mockito.when(jwtUtils.validateToken(invalidToken, tokenType)).thenReturn(false);

        ApiException apiException = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount(invalidToken)
        );

        assertEquals("Invalid confirmation token.", apiException.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, apiException.getStatus());
        assertEquals(AuthCodes.INVALID_TOKEN.name(), apiException.getCode());
    }

    @Test
    public void shouldHandleUserNotFound() {
        String validToken = "valid_token";
        String email = "user@example.com";

        Mockito.when(jwtUtils.validateToken(validToken, TokenType.CONFIRMATION)).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(validToken)).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(null);

        ApiException exception = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount(validToken)
        );

        assertEquals("User not found", exception.getMessage());
        assertEquals( HttpStatus.NOT_FOUND, exception.getStatus());
        assertEquals(AuthCodes.USER_NOT_FOUND.name(), exception.getCode());
    }

    @Test
    public void shouldNotSendConfirmationEmailIfUserAlreadyConfirmed() throws MessagingException {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);
        authUser.setRoles(Set.of(new Role("CLIENT")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        confirmUserService.sendConfirmationEmail(authUser);

        Mockito.verify(emailSender, Mockito.times(0))
                .sendEmail(Mockito.eq(authUser.getEmail()), Mockito.anyString(), Mockito.any(), Mockito.eq("client.registration"));
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

        Mockito.when(jwtUtils.validateToken(validToken, TokenType.CONFIRMATION)).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(validToken)).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(appUser);
        Mockito.when(authUserRepository.save(authUser)).thenReturn(authUser);

        confirmUserService.confirmUserAccount(validToken);

        Mockito.verify(authUserRepository, Mockito.times(1)).save(authUser);
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

        Mockito.when(jwtUtils.validateToken(Mockito.anyString(), Mockito.any(TokenType.class))).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(Mockito.anyString())).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(appUser);

        Mockito.doThrow(new ApiException("User with email " + email + " is already confirmed",
                        HttpStatus.BAD_REQUEST,
                        AuthCodes.USER_ALREADY_CONFIRMED.name()))
                .when(exceptionHandlerService).handleUserAlreadyConfirmedException(email);

        ApiException exception = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount("valid_token")
        );

        assertEquals("User with email " + email + " is already confirmed", exception.getMessage());
        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatus());
        assertEquals(AuthCodes.USER_ALREADY_CONFIRMED.name(), exception.getCode());

        Mockito.verify(exceptionHandlerService).handleUserAlreadyConfirmedException(email);
    }

    @Test
    public void shouldSendConfirmationEmailToAdminIfUserIsInstructor() throws MessagingException {
        String email = "instructor@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);
        authUser.setRoles(Set.of(new Role("INSTRUCTOR")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        AuthUser adminUser = new AuthUser();
        adminUser.setEmail("admin@example.com");

        Mockito.when(authUserRepository.findAdminUser()).thenReturn(adminUser);

        confirmUserService.sendConfirmationEmail(authUser);
        Mockito.verify(emailSender).sendEmail(adminUser.getEmail(), null, Locale.ENGLISH, "admin.approval");
        Mockito.verify(emailSender).sendEmailWithoutConfirmationLink(Mockito.eq(authUser.getEmail()), Mockito.any(), Mockito.eq("instructor.registration"));
    }

    @Test
    public void shouldSendConfirmationEmailToUserIfNotInstructor() throws MessagingException {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);
        authUser.setRoles(Set.of(new Role("CLIENT")));

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        confirmUserService.sendConfirmationEmail(authUser);

        Mockito.verify(emailSender).sendEmail(authUser.getEmail(), null, Locale.ENGLISH, "client.registration");
    }

    @Test
    public void shouldSendConfirmationSuccessEmailWhenAccountIsConfirmed() throws MessagingException {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        Mockito.doNothing().when(emailSender).sendEmailWithoutConfirmationLink(Mockito.anyString(), Mockito.any(), Mockito.eq("account.confirmed"));

        confirmUserService.sendConfirmationSuccessEmail(authUser);

        Mockito.verify(emailSender, Mockito.times(1)).sendEmailWithoutConfirmationLink(authUser.getEmail(), Locale.ENGLISH, "account.confirmed");
    }
}
