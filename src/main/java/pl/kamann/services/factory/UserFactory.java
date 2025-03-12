package pl.kamann.services.factory;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.kamann.dtos.register.RegisterRequest;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.AuthUserStatus;
import pl.kamann.entities.appuser.Role;

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