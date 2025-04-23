/**
 * Ubiquitous Language Summary:
 * Application service responsible for extracting and validating the current authenticated user
 * from a JWT token present in the incoming request.
 */
package pl.kamann.application.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.mapper.AppUserMapper;
import pl.kamann.domain.appuser.AppUser;
import pl.kamann.domain.appuser.dto.AppUserDto;
import pl.kamann.domain.appuser.lookup.UserLookupService;
import pl.kamann.domain.authuser.Email;
import pl.kamann.infrastructure.security.jwt.JwtUtils;

@Service
@RequiredArgsConstructor
public class GetLoggedInUserService {

    private final JwtUtils jwtUtils;
    private final UserLookupService userLookupService;
    private final AppUserMapper appUserMapper;

    @Transactional(readOnly = true)
    public AppUserDto getLoggedInUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        jwtUtils.validateToken(token);

        Email email = new Email(jwtUtils.extractEmail(token));
        AppUser appUser = userLookupService.findUserByEmail(email.getValue())
                .orElseThrow(() -> new IllegalStateException("User with email not found: " + email.getValue()));

        return appUserMapper.toAppUserDto(appUser);
    }

    @Transactional(readOnly = true)
    public AppUser getLoggedInDomainUser(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        jwtUtils.validateToken(token);
        Email email = new Email(jwtUtils.extractEmail(token));
        return userLookupService.findUserByEmail(email.getValue())
                .orElseThrow(() -> new IllegalStateException("User not found with email: " + email.getValue()));
    }
}