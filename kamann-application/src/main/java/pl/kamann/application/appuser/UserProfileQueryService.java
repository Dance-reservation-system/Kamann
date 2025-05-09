package pl.kamann.application.appuser;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pl.kamann.application.authuser.lookup.AppUserFinder;
import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.security.jwt.JwtUtils;

@Service
public class UserProfileQueryService {

    private final JwtUtils jwtUtils;
    private final AppUserFinder appUserFinder;
    private final AppUserMapper mapper;

    public UserProfileQueryService(JwtUtils jwtUtils,
                                   AppUserFinder appUserFinder,
                                   AppUserMapper mapper) {
        this.jwtUtils = jwtUtils;
        this.appUserFinder = appUserFinder;
        this.mapper = mapper;
    }

    @Transactional(readOnly = true)
    public AppUserProfileDto getCurrentUserProfile(HttpServletRequest request) {
        String token = jwtUtils.extractTokenFromRequest(request);
        jwtUtils.validateToken(token);

        Email email = new Email(jwtUtils.extractEmail(token));

        AppUser user = appUserFinder.findByEmail(email.value())
                .orElseThrow(() -> new IllegalStateException("User not found: " + email.value()));

        return mapper.toProfileDto(user);
    }
}
