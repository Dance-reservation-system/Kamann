package pl.kamann.services;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.mail.MessagingException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.dtos.ResetPasswordRequest;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.TokenType;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.services.email.EmailSender;
import pl.kamann.testcontainers.config.TestContainersConfig;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
@Import(TestContainersConfig.class)
public class PasswordResetServiceTest {

    @MockBean
    private EmailSender emailSender;

    @MockBean
    private JwtUtils jwtUtils;

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private AppUserRepository appUserRepository;

    @Test
    void shouldRequestPasswordReset() throws MessagingException {
        AppUser appUser = new AppUser();
        appUser.setFirstName("John");
        appUser.setLastName("Doe");
        appUser.setPhone("123456789");

        AuthUser user = new AuthUser();
        user.setEmail("test@test.com");
        user.setPassword("old_Password");
        user.setEnabled(true);
        user.setAppUser(appUser);
        appUser.setAuthUser(user);

        authUserRepository.save(user);
        appUserRepository.save(appUser);

        doNothing().when(emailSender).sendEmail(anyString(), anyString(), any(Locale.class), anyString());

        passwordResetService.requestPasswordReset(user.getEmail());

        verify(emailSender).sendEmail(anyString(), anyString(), any(Locale.class), anyString());
    }

    @Test
    void shouldResetPasswordWithToken() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken(generateValidJwtToken("test@test.com"));
        request.setNewPassword("new_password");

        String email = "test@test.com";
        AuthUser authUser = new AuthUser();

        AppUser appUser = new AppUser();
        appUser.setFirstName("John");
        appUser.setLastName("Doe");

        authUser.setEmail(email);
        authUser.setPassword(passwordEncoder.encode("old_password"));
        authUser.setAppUser(appUser);

        appUser.setAuthUser(authUser);
        authUserRepository.save(authUser);

        appUser.setAuthUser(authUser);

        appUserRepository.save(appUser);

        when(jwtUtils.validateToken(request.getToken(), TokenType.RESET_PASSWORD)).thenReturn(true);
        when(jwtUtils.extractEmail(request.getToken())).thenReturn(email);

        passwordResetService.resetPasswordWithToken(request);

        AuthUser updatedUser = authUserRepository.findByEmail(authUser.getEmail()).orElseThrow();
        assertTrue(passwordEncoder.matches("new_password", updatedUser.getPassword()), "Password should be updated");
    }



    @Test
    void shouldThrowExceptionForInvalidToken() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken("invalid_token");
        request.setNewPassword("new_password");

        ApiException exception = assertThrows(ApiException.class, () ->
                passwordResetService.resetPasswordWithToken(request)
        );
        assertTrue(exception.getMessage().contains("Invalid reset password token"));
    }

    @Test
    void shouldThrowExceptionForExpiredToken() {
        ResetPasswordRequest request = new ResetPasswordRequest();
        request.setToken(generateExpiredJwtToken("test@test.com"));
        request.setNewPassword("new_password");

        AppUser appUser = new AppUser();
        appUser.setFirstName("John");
        appUser.setLastName("Doe");
        appUser.setPhone("123456789");

        AuthUser authUser = new AuthUser();
        authUser.setEmail("test@test.com");
        authUser.setPassword("hashed_password");

        appUser.setAuthUser(authUser);

        authUserRepository.save(authUser);
        appUserRepository.save(appUser);

        ApiException exception = assertThrows(ApiException.class, () ->
                passwordResetService.resetPasswordWithToken(request)
        );

        assertTrue(exception.getMessage().contains("Invalid reset password token."));
    }

    @Test
    void shouldThrowExceptionForUserNotFound() {
        ApiException exception = assertThrows(ApiException.class, () ->
                passwordResetService.requestPasswordReset("nonexistent@test.com")
        );
        assertTrue(exception.getMessage().contains("User with email: nonexistent@test.com not found"));
    }

    @Test
    void shouldThrowExceptionForErrorSendingEmail() throws MessagingException {
        AppUser appUser = new AppUser();
        appUser.setFirstName("John");
        appUser.setLastName("Doe");
        appUser.setPhone("123456789");

        AuthUser user = new AuthUser();
        user.setEmail("test@test.com");
        user.setPassword("hashed_password");
        user.setAppUser(appUser);
        appUser.setAuthUser(user);

        authUserRepository.save(user);
        appUserRepository.save(appUser);

        doThrow(new MessagingException("Error sending email"))
                .when(emailSender).sendEmail(anyString(), anyString(), any(Locale.class), anyString());

        ApiException exception = assertThrows(ApiException.class, () ->
                passwordResetService.requestPasswordReset(user.getEmail())
        );

        assertTrue(exception.getMessage().contains("Your account is not active. Please contact support."));
    }

    private String generateValidJwtToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 3600000);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .claim("TokenType", TokenType.CONFIRMATION.toString())
                .signWith(jwtUtils.getSecretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private String generateExpiredJwtToken(String email) {
        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

        when(jwtUtils.getSecretKey()).thenReturn(secretKey);

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() - 3600000); // expired by 1 hour

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .claim("TokenType", TokenType.RESET_PASSWORD.toString())
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }
}