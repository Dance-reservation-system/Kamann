package pl.kamann.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import pl.kamann.config.codes.AuthCodes;
import pl.kamann.config.codes.RoleCodes;
import pl.kamann.config.exception.handler.ApiException;
import pl.kamann.config.security.jwt.JwtUtils;
import pl.kamann.dtos.AppUserDto;
import pl.kamann.dtos.AppUserResponseDto;
import pl.kamann.dtos.login.LoginRequest;
import pl.kamann.dtos.login.LoginResponse;
import pl.kamann.dtos.register.RegisterRequest;
import pl.kamann.entities.appuser.AppUser;
import pl.kamann.entities.appuser.AuthUser;
import pl.kamann.entities.appuser.Role;
import pl.kamann.mappers.AppUserMapper;
import pl.kamann.repositories.AppUserRepository;
import pl.kamann.repositories.AuthUserRepository;
import pl.kamann.repositories.RoleRepository;
import pl.kamann.services.factory.UserFactory;
import pl.kamann.config.exception.services.ValidationService;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    private final ConfirmUserService confirmUserService;
    private final UserFactory userFactory;
    private final AppUserMapper appUserMapper;

    private final RoleRepository roleRepository;
    private final AppUserRepository appUserRepository;
    private final AuthUserRepository authUserRepository;

    private final ValidationService validationService;

    public LoginResponse login(@Valid LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );

            AuthUser authUser = (AuthUser) authentication.getPrincipal();
            log.info("User logged in successfully: email={}", authUser.getEmail());
            return new LoginResponse(jwtUtils.generateToken(authUser.getEmail(), authUser.getRoles()));
        } catch (DisabledException e) {
            log.warn("Attempted login with unconfirmed email: {}", request.email());
            throw new ApiException(
                    "Email not confirmed.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.EMAIL_NOT_CONFIRMED.name()
            );
        } catch (BadCredentialsException e) {
            log.warn("Invalid User credentials attempt for email: {}", request.email());
            throw new ApiException(
                    "Invalid user credentials.",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.UNAUTHORIZED.name()
            );
        }
    }

    @Transactional
    public AppUserDto registerClient(RegisterRequest request) {
        return registerUser(request, RoleCodes.CLIENT.name());
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return registerUser(request, RoleCodes.INSTRUCTOR.name());
    }

    private AppUserDto registerUser(RegisterRequest request, String roleCode) {
        validationService.validateEmailNotTaken(request.email());
        Role role = findRoleByName(roleCode);

        AppUser appUser = userFactory.createAppUser(request);
        AuthUser authUser = userFactory.createAndLinkAuthWithApp(request, role, appUser);

        authUserRepository.save(authUser);
        AppUser savedAppUser = appUserRepository.save(appUser);

        confirmUserService.sendConfirmationEmail(authUser);

        log.info("User registered successfully: email={}, role={}", request.email(), role.getName());
        return appUserMapper.toAppUserDto(savedAppUser);
    }

    public Role findRoleByName(String roleName) {
        return roleRepository.findByName(roleName)
                .orElseThrow(() -> new ApiException(
                        "Role not found: " + roleName,
                        HttpStatus.NOT_FOUND,
                        AuthCodes.ROLE_NOT_FOUND.name()
                ));
    }

    public AppUserResponseDto getLoggedInAppUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request)
                .orElseThrow(() -> new ApiException("Invalid or missing token",
                        HttpStatus.UNAUTHORIZED,
                        AuthCodes.INVALID_TOKEN.name()));

        if (!jwtUtils.validateToken(token)) {
            throw new ApiException("Invalid or expired token",
                    HttpStatus.UNAUTHORIZED,
                    AuthCodes.INVALID_TOKEN.name());
        }

        String email = jwtUtils.extractEmail(token);

        AuthUser authUser = authUserRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException("User not found",
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));

        AppUser appUser = appUserRepository.findByAuthUser(authUser)
                .orElseThrow(() -> new ApiException("User profile not found",
                        HttpStatus.NOT_FOUND,
                        AuthCodes.USER_NOT_FOUND.name()));

        return appUserMapper.toAppUserResponseDto(appUser);
    }
}