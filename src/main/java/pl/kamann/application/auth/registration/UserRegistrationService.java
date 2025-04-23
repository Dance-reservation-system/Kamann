/**
 * Ubiquitous Language Summary:
 * Application Service responsible for registering new users, including account creation,
 * domain validation, persistence, and confirmation email dispatch.
 */
package pl.kamann.application.auth.registration;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import pl.kamann.application.auth.EmailConfirmationFacade;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.Role;
import pl.kamann.domain.appuser.lookup.RoleLookupService;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.authuser.AuthUser;
import pl.kamann.domain.authuser.Email;
import pl.kamann.domain.authuser.RoleCodes;
import pl.kamann.domain.authuser.dto.RegisterRequest;
import pl.kamann.domain.authuser.validation.AuthUserValidator;
import pl.kamann.domain.user.UserFactory;
import pl.kamann.infrastructure.security.RawAuthUserInput;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserRegistrationService {

    private final AuthUserValidator authUserValidator;
    private final UserFactory userFactory;
    private final RoleLookupService roleLookupService;
    private final AppUserMapper appUserMapper;
    private final EmailConfirmationFacade emailConfirmationFacade;
    private final UserPersister userPersister;

    @Transactional
    public AppUserDto registerUser(RegisterRequest request, String roleCode) {
        authUserValidator.validateEmailNotTaken(new Email(request.email()));

        Role role = roleLookupService.findRoleByName(roleCode);
        RawAuthUserInput rawUser = new RawAuthUserInput(
                request.email(),
                request.password(),
                Set.of(role)
        );

        CreatedUser userPair = createAndLinkUsers(request, rawUser);
        userPersister.save(userPair.authUser(), userPair.appUser());

        emailConfirmationFacade.sendConfirmationEmail(userPair.authUser());

        return appUserMapper.toAppUserDto(userPair.appUser());
    }

    @Transactional
    public AppUserDto registerClient(RegisterRequest request) {
        return registerUser(request, RoleCodes.CLIENT.name());
    }

    @Transactional
    public AppUserDto registerInstructor(RegisterRequest request) {
        return registerUser(request, RoleCodes.INSTRUCTOR.name());
    }

    private CreatedUser createAndLinkUsers(RegisterRequest request, RawAuthUserInput rawUser) {
        var userAggregate = userFactory.createFullUser(
                request.firstName(),
                request.lastName(),
                request.phone(),
                rawUser
        );
        return new CreatedUser(userAggregate.authUser(), userAggregate.appUser());
    }

    private record CreatedUser(AuthUser authUser, AppUser appUser) {}
}
