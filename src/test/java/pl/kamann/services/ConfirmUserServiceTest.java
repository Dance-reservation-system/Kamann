package pl.kamann.services;

import jakarta.mail.MessagingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
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
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.email.EmailSender;
import pl.kamann.testcontainers.config.TestContainersConfig;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    public void shouldConfirmAccount() {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(false);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        Mockito.when(jwtUtils.validateToken(Mockito.anyString())).thenReturn(true);
        Mockito.when(jwtUtils.isTokenTypeValid(Mockito.anyString(), Mockito.any())).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(Mockito.anyString())).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(appUser);
        Mockito.when(appUserRepository.existsByAuthUser(authUser)).thenReturn(false);

        Mockito.when(appUserRepository.save(Mockito.any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        confirmUserService.confirmUserAccount("valid_token");

        Mockito.verify(appUserRepository).save(Mockito.argThat(savedAppUser ->
                savedAppUser.getAuthUser().equals(authUser) && savedAppUser.getAuthUser().getEmail().equals(email)
        ));

        Mockito.verify(authUserRepository).save(authUser);
    }


    @Test
    public void shouldHandleInvalidToken() {
        String invalidToken = "invalid_token";
        Mockito.when(jwtUtils.validateToken(invalidToken)).thenReturn(false);

        Mockito.doNothing().when(exceptionHandlerService).handleInvalidTokenException();
        confirmUserService.confirmUserAccount(invalidToken);
        Mockito.verify(exceptionHandlerService, Mockito.times(1)).handleInvalidTokenException();
    }

    @Test
    public void shouldHandleUserNotFound() {
        String validToken = "valid_token";
        String email = "user@example.com";

        Mockito.when(jwtUtils.validateToken(validToken)).thenReturn(true);
        Mockito.when(jwtUtils.isTokenTypeValid(validToken, TokenType.CONFIRMATION)).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(validToken)).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(null);

        Mockito.doNothing().when(exceptionHandlerService).handleUserNotFoundException(email);
        confirmUserService.confirmUserAccount(validToken);
        Mockito.verify(exceptionHandlerService, Mockito.times(1)).handleUserNotFoundException(email);
    }

    @Test
    public void shouldNotSendConfirmationEmailIfUserAlreadyConfirmed() throws MessagingException {
        String email = "user@example.com";

        AuthUser authUser = new AuthUser();
        authUser.setEmail(email);
        authUser.setEnabled(true);

        AppUser appUser = new AppUser();
        appUser.setAuthUser(authUser);

        confirmUserService.sendConfirmationEmail(authUser);

        Mockito.verify(emailSender, Mockito.times(0))
                .sendEmail(Mockito.eq(authUser.getEmail()), Mockito.anyString(), Mockito.any(), Mockito.eq("registration"));
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

        Mockito.when(jwtUtils.validateToken(validToken)).thenReturn(true);
        Mockito.when(jwtUtils.isTokenTypeValid(validToken, TokenType.CONFIRMATION)).thenReturn(true);
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

        Mockito.when(jwtUtils.validateToken(Mockito.anyString())).thenReturn(true);
        Mockito.when(jwtUtils.isTokenTypeValid(Mockito.anyString(), Mockito.any())).thenReturn(true);
        Mockito.when(jwtUtils.extractEmail(Mockito.anyString())).thenReturn(email);
        Mockito.when(userLookupService.findUserByEmail(email)).thenReturn(appUser);

        Mockito.doThrow(new ApiException("User with email " + email + " is already confirmed",
                        HttpStatus.BAD_REQUEST,
                        AuthCodes.USER_ALREADY_CONFIRMED.name()))
                .when(exceptionHandlerService).handleUserAlreadyConfirmedException(email);

        ApiException exception = assertThrows(ApiException.class, () ->
                confirmUserService.confirmUserAccount("valid_token")
        );

        assertTrue(exception.getMessage().contains("User with email " + email + " is already confirmed"));

        Mockito.verify(exceptionHandlerService).handleUserAlreadyConfirmedException(email);
    }
}
