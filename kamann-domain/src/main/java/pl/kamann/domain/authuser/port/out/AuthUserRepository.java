package pl.kamann.domain.authuser.port.out;

import pl.kamann.domain.appuser.aggregate.AppUser;
import pl.kamann.domain.authuser.aggregate.AuthUser;
import pl.kamann.domain.authuser.vo.AuthUserId;
import pl.kamann.domain.authuser.vo.Email;
import pl.kamann.domain.authuser.vo.Role;

import java.util.List;
import java.util.Optional;

/**
 * Domain port for loading and saving AuthUser aggregates.
 * No framework or pagination types here.
 */
public interface AuthUserRepository {
    Optional<AuthUser> findByEmail(Email email);
    Optional<AuthUser> findById(AuthUserId id);
    void save(AuthUser user);
    void delete(AuthUser user);
    Optional<AppUser> findByAuthUser(AuthUser user);

    List<AuthUser> findByRole(Role admin);
}
