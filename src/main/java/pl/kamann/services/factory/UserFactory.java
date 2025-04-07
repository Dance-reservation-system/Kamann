package pl.kamann.services.factory;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.kamann.dtos.register.RegisterRequest;
import pl.kamann.entities.appuser.*;

import java.time.LocalDateTime;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class UserFactory {

    private final PasswordEncoder passwordEncoder;

    private AppUser createAppUser(String firstName, String lastName) {
        return AppUser.builder()
                .firstName(firstName)
                .lastName(lastName)
                .createdAt(LocalDateTime.now())
                .build();
    }

    private AppUser createAppUserWithPhone(RegisterRequest request) {
        AppUser appuser = createAppUser(request.firstName(), request.lastName());
        appuser.setPhone(request.phone());

        return appuser;
    }

    private AuthUser buildAuthUser(String email, LoginProvider loginProvider, Role role, AuthUserStatus status, boolean enabled) {
        return AuthUser.builder()
                .email(email)
                .loginProvider(loginProvider)
                .roles(Set.of(role))
                .status(status)
                .enabled(enabled)
                .build();
    }

    public AuthUser createAuthUserWithPasswordAndLinkToAppUser(RegisterRequest request, Role role) {
        AppUser appUser = createAppUserWithPhone(request);

        AuthUser authUser = buildAuthUser(request.email(), LoginProvider.LOCAL, role, AuthUserStatus.PENDING, false);
        authUser.setPassword(passwordEncoder.encode(request.password()));

        authUser.setAppUser(appUser);
        appUser.setAuthUser(authUser);

        return authUser;
    }

    public AuthUser createAuthUserWithOAuthAndLinkToAppUser(String email, String firstName, String lastName, Role role) {
        AppUser appUser = createAppUser(firstName, lastName);

        AuthUser authUser = buildAuthUser(email, LoginProvider.GOOGLE, role, AuthUserStatus.ACTIVE, true);

        authUser.setAppUser(appUser);
        appUser.setAuthUser(authUser);

        return authUser;
    }
}