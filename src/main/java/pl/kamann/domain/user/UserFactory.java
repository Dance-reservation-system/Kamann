package pl.kamann.domain.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.AuthUserStatus;
import pl.kamann.domain.appuser.Role;

import java.time.LocalDateTime;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class UserFactory {

    private final PasswordEncoder passwordEncoder;

    public AuthUser createAndLinkAuthWithApp(RegisterRequest request, Role role, AppUser appUser) {
        AuthUser authUser = AuthUser.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(Set.of(role))
                .status(AuthUserStatus.PENDING)
                .enabled(false)
                .build();

        authUser.setAppUser(appUser);
        appUser.setAuthUser(authUser);

        return authUser;
    }

    public AppUser createAppUser(RegisterRequest request) {
        return AppUser.builder()
                        .firstName(request.firstName())
                        .lastName(request.lastName())
                        .createdAt(LocalDateTime.now())
                        .phone(request.phone())
                        .build();
    }
}