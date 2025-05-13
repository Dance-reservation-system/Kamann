package pl.kamann.web.auth;

import pl.kamann.domain.authuser.aggregate.AuthUser;
import shared.LoginResponse;

/**
 * Ubiquitous Language Summary:
 * Mapper for converting AuthUser aggregate to DTOs like LoginResponse.
 */

public interface AuthUserMapper {

    LoginResponse toLoginResponse(AuthUser user);

    default String map(pl.kamann.domain.authuser.vo.Email email) {
        return email != null ? email.value() : null;
    }
}